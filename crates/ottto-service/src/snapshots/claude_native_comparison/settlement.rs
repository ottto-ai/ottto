//! Ephemeral comparison deferral at the existing selected-index save seams.
//! No refusal, account row, persisted hold or alternate ACK ledger is created.
use super::*;

pub(crate) struct Completion {
    reservation: Option<crate::source_rotation::PaidReservation>,
    pub(crate) window: Option<Box<WindowEligibility>>,
    pub(crate) fallback: Option<SelectedFallback>,
    native_plans: BTreeMap<String, NativePlan>,
    pending_corrections: Vec<PendingNativeCorrection>,
    target_charges: TargetChargeReceipts,
    native_terminal: Option<NativeCensusCompletion>,
}

/// Move-only accounting provenance, never evidence/ownership/Skip/coverage.
/// The map is not exposed to billing or tagging decisions. A source match can
/// ONLY select which added allocation must be paid, never what may be sent.
#[derive(Default)]
struct TargetChargeReceipts {
    revisions: DescriptorMap<String>,
}
impl TargetChargeReceipts {
    fn appended(scan: &SourceScanResult, frontier: Option<usize>) -> Option<&[SnapshotItem]> {
        match frontier {
            Some(frontier) => (scan.source == SnapshotSource::ClaudeCode)
                .then(|| scan.snapshots.get(frontier..))
                .flatten(),
            None => {
                #[cfg(test)]
                {
                    Some(&[])
                } // explicit logical adapter, never runtime provenance
                #[cfg(not(test))]
                {
                    None
                } // a production caller cannot bypass the producer binding
            }
        }
    }
    fn construction_peak(scan: &SourceScanResult, frontier: Option<usize>) -> Option<usize> {
        use crate::heap_layout_bound::Counter;
        let appended = Self::appended(scan, frontier)?;
        let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
        cost.add(
            appended
                .len()
                .checked_mul(std::mem::size_of::<(String, String)>())?,
        )?;
        // Count each possible output, even duplicate source ids: constructor
        // replacement strings may coexist with the previous receipt.
        for item in appended {
            let revision = item
                .source_file_fingerprint
                .as_deref()
                .filter(|fp| !fp.is_empty())?;
            if item.source_session_id.is_empty() {
                return None;
            }
            cost.add(item.source_session_id.len())?;
            cost.add(revision.len())?;
        }
        Some(cost.bytes)
    }
    fn capture(scan: &SourceScanResult, frontier: Option<usize>) -> Result<Self, &'static str> {
        let appended =
            Self::appended(scan, frontier).ok_or("native target output frontier is unknown")?;
        let mut revisions = DescriptorMap::default();
        revisions
            .reserve_merge(appended.len())
            .ok_or("native target charge buffer is unavailable")?;
        for item in appended {
            let revision = item
                .source_file_fingerprint
                .as_deref()
                .filter(|fp| !fp.is_empty())
                .ok_or("native target output revision is unknown")?;
            if item.source_session_id.is_empty()
                || revisions
                    .get(&item.source_session_id)
                    .is_some_and(|saved| saved != revision)
            {
                return Err("native target output charge provenance conflicts");
            }
            revisions.insert(item.source_session_id.clone(), revision.to_owned());
        }
        if !revisions.accounted() {
            return Err("native target output charge accounting is unknown");
        }
        Ok(Self { revisions })
    }
}

pub(super) struct NativePlan {
    root: String,
    proof: String,
    revision: String,
}
pub(super) struct NativeCorrection {
    root: String,
    proof: String,
    revision: String,
    fingerprint: String,
    body_witness: String,
    selected_fingerprint: String,
    selected_body_witness: String,
}
impl std::fmt::Debug for NativeCorrection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DurableNativeCorrection")
    }
}
struct PendingNativeCorrection {
    key: String,
    plan: NativePlan,
    fingerprint: String,
    body_witness: String,
}

/// Optional correction metadata shares the SAME moving reservation. A
/// refusal only declines a future optimization receipt; it cannot alter an
/// offered body, selected ACK, or mandatory recovery credit. Retain a
/// conservative construction upper bound until this completion is dropped.
fn prepay_correction_metadata(
    reservation: &mut Option<crate::source_rotation::PaidReservation>,
    bytes: Option<usize>,
) -> Option<usize> {
    let bytes = bytes?;
    match reservation.as_mut() {
        Some(paid) => {
            let owned = paid.allocated().checked_add(bytes)?;
            paid.grow_for(owned).then_some(owned)
        }
        None => {
            #[cfg(test)]
            {
                Some(0)
            } // Explicit logical primitive; no physical admission claim.
            #[cfg(not(test))]
            {
                None
            }
        }
    }
}
fn retain_correction_metadata(
    reservation: &mut Option<crate::source_rotation::PaidReservation>,
    owned: usize,
) -> bool {
    match reservation.as_mut() {
        Some(paid) => paid.record_allocated(owned),
        None => cfg!(test),
    }
}

impl NativeCorrection {
    pub(super) fn root(&self) -> &str {
        &self.root
    }
    pub(super) fn current(&self, key: &str, index: &ScanIndex) -> bool {
        !index
            .claude_usage_authority_quarantine
            .contains_key(&self.root)
            && !index.claude_account_deferred_holds.contains_key(key)
            && index
                .claude_usage_family_witnesses
                .get(&self.root)
                .is_some_and(|witness| {
                    claude_usage_family_witness_fingerprint(witness) == self.proof
                })
            && index.files.get(key).is_some_and(|entry| {
                entry.source_file_fingerprint == self.revision
                    && entry.scan_identity_version.as_deref()
                        == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
                    && entry.last_snapshot_fingerprint.as_ref() == Some(&self.selected_fingerprint)
                    && entry.last_upload_body_witness.as_ref() == Some(&self.selected_body_witness)
            })
            && index
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|fps| fps.len() == 1 && fps.contains(&self.fingerprint))
            && index
                .accepted_snapshot_fingerprints
                .contains(&self.fingerprint)
            && !index
                .quarantined_snapshot_fingerprints
                .contains_key(&self.fingerprint)
            && !index.confirmed_empty_files.contains(key)
            && !index.terminal_jsonl_dispositions.contains_key(key)
    }
}

/// A borrow of the SAME completion reservation and its immutable producer
/// receipts. No allowance is created here. Only allocation provenance is
/// consulted; callers cannot use this view as identity/coverage evidence.
pub(crate) struct NativeBodyBudget<'a> {
    paid: &'a mut crate::source_rotation::PaidReservation,
    targets: &'a TargetChargeReceipts,
}
pub(in crate::snapshots) struct NativeObservationConstruction<'a> {
    paid: &'a mut crate::source_rotation::PaidReservation,
    old_allocated: usize,
    old_ceiling: usize,
    retained: usize,
}
impl NativeObservationConstruction<'_> {
    pub(in crate::snapshots) fn finish(self) -> Result<(), crate::source_rotation::LocalRefusal> {
        let refusal = crate::source_rotation::LocalRefusal(
            "native observation ownership exceeded prepayment",
        );
        let owned = self
            .old_allocated
            .checked_add(self.retained)
            .ok_or(refusal)?;
        if !self.paid.record_allocated(owned) {
            return Err(refusal);
        }
        self.paid.release_temporary_peak(self.old_ceiling);
        Ok(())
    }
}
impl NativeBodyBudget<'_> {
    pub(in crate::snapshots) fn before_native_observation(
        &mut self,
        item: &SnapshotItem,
        pending: &BTreeMap<String, ClaudeUsageFamilyPending>,
        window: &str,
    ) -> Result<Option<NativeObservationConstruction<'_>>, crate::source_rotation::LocalRefusal>
    {
        use crate::heap_layout_bound::{self, Counter};
        let refusal = crate::source_rotation::LocalRefusal(
            "native observation construction cannot be prepaid",
        );
        let Some(revision) = self.targets.revisions.get(&item.source_session_id) else {
            // Ordinary bodies still use the same single canonical accumulator.
            // No additional copy/retention is introduced for them by this call.
            return Ok(None);
        };
        if item.source_file_fingerprint.as_ref() != Some(revision) {
            return Err(refusal);
        }
        let root = claude_snapshot_family_root_ref(item);
        let previous = pending.get(root);
        let reset = previous.map_or(true, |previous| previous.census_window_end != window);
        let mut retained = Counter::new(crate::source_rotation::PARKED_BUDGET);
        if previous.is_none() {
            restore_tree_insert_peak::<String, ClaudeUsageFamilyPending>(
                pending.len().checked_add(1).ok_or(refusal)?,
                1,
                &mut retained,
            )
            .ok_or(refusal)?;
            retained.add(root.len()).ok_or(refusal)?;
        }
        if reset {
            retained.add(window.len()).ok_or(refusal)?;
        }
        let mut temporary = Counter::new(crate::source_rotation::PARKED_BUDGET);
        temporary.add(root.len()).ok_or(refusal)?; // canonical root String before entry
        if !previous.is_some_and(|previous| !reset && previous.invalid) {
            let hash_count = item.claude_usage_request_ids.len();
            let occurrence_count = item.claude_usage_occurrences.len();
            // Installed pending member graphs, before replacing any old state.
            heap_layout_bound::tree_nodes::<String, ()>(hash_count, &mut retained)
                .ok_or(refusal)?;
            heap_layout_bound::tree_nodes::<String, ClaudeTranscriptUsageOccurrenceWitness>(
                occurrence_count,
                &mut retained,
            )
            .ok_or(refusal)?;
            retained
                .add(
                    hash_count
                        .checked_add(occurrence_count)
                        .and_then(|n| n.checked_mul(64))
                        .ok_or(refusal)?,
                )
                .ok_or(refusal)?;
            let text = item
                .claude_usage_occurrences
                .values()
                .try_fold(0usize, |n, occurrence| {
                    n.checked_add(occurrence.model.as_ref().map_or(0, String::len))?
                        .checked_add(occurrence.reasoning_effort.as_ref().map_or(0, String::len))?
                        .checked_add(
                            occurrence
                                .selector
                                .context
                                .get("speed_mode")
                                .map_or(0, String::len),
                        )
                })
                .ok_or(refusal)?;
            retained.add(text).ok_or(refusal)?;
            let members = previous.filter(|_| !reset).map_or(0, |p| {
                p.member_occurrences
                    .len()
                    .max(p.member_request_id_hashes.len())
            });
            restore_tree_insert_peak::<String, BTreeSet<String>>(
                members.checked_add(1).ok_or(refusal)?,
                1,
                &mut retained,
            )
            .ok_or(refusal)?;
            restore_tree_insert_peak::<
                String,
                BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>,
            >(members.checked_add(1).ok_or(refusal)?, 1, &mut retained)
            .ok_or(refusal)?;
            retained
                .add(item.source_session_id.len().checked_mul(2).ok_or(refusal)?)
                .ok_or(refusal)?;
            // The unchanged canonical code keeps local maps while cloning its
            // installed maps. Its equality check creates one more temporary
            // hash set. Price those exact existing allocations, not a second
            // observation fold or a projection of output bodies.
            heap_layout_bound::tree_nodes::<String, ()>(hash_count, &mut temporary)
                .ok_or(refusal)?;
            heap_layout_bound::tree_nodes::<String, ()>(occurrence_count, &mut temporary)
                .ok_or(refusal)?;
            heap_layout_bound::tree_nodes::<String, ClaudeTranscriptUsageOccurrenceWitness>(
                occurrence_count,
                &mut temporary,
            )
            .ok_or(refusal)?;
            temporary
                .add(
                    hash_count
                        .checked_add(occurrence_count.checked_mul(2).ok_or(refusal)?)
                        .and_then(|n| n.checked_mul(64))
                        .ok_or(refusal)?,
                )
                .ok_or(refusal)?;
            temporary.add(text).ok_or(refusal)?;
            temporary.add(384).ok_or(refusal)?; // current digest formatting old/new buffers
        }
        let old_allocated = self.paid.allocated();
        let old_ceiling = self.paid.allocation_ceiling();
        let peak = old_allocated
            .checked_add(retained.bytes)
            .and_then(|n| n.checked_add(temporary.bytes))
            .ok_or(refusal)?;
        if !self.paid.grow_for(peak) {
            return Err(refusal);
        }
        Ok(Some(NativeObservationConstruction {
            paid: self.paid,
            old_allocated,
            old_ceiling,
            retained: retained.bytes,
        }))
    }
}

impl Completion {
    pub(crate) fn record_native_observations_paid(
        &mut self,
        scan: &SourceScanResult,
        index: &mut ScanIndex,
    ) -> Result<Option<ClaudeNativeObservations>, crate::source_rotation::LocalRefusal> {
        if !index.persistence_available() {
            return Err(crate::source_rotation::LocalRefusal(
                "scan_index_map_unavailable",
            ));
        }

        let active = self.fallback.is_some()
            || !self.target_charges.revisions.is_empty()
            || self
                .window
                .as_ref()
                .is_some_and(|window| !window.roots.is_empty());
        if !active {
            // No emission filtering requires an early observation receipt.
            // The unchanged final canonical fold performs this work once.
            return Ok(None);
        }
        let Some(paid) = self.reservation.as_mut() else {
            #[cfg(test)]
            return Ok(Some(record_claude_native_observations(scan, index)));
            #[cfg(not(test))]
            return Err(crate::source_rotation::LocalRefusal(
                "native observation reservation is missing",
            ));
        };
        let refusal =
            crate::source_rotation::LocalRefusal("native observation receipt cannot be prepaid");
        let owned = paid
            .allocated()
            .checked_add(scan.census_window_end.len())
            .ok_or(refusal)?;
        if !paid.grow_for(owned) {
            return Err(refusal);
        }
        let window = scan.census_window_end.clone();
        if !paid.record_allocated(owned) {
            return Err(refusal);
        }
        let mut budget = NativeBodyBudget {
            paid,
            targets: &self.target_charges,
        };
        let counts = accumulate_claude_usage_family_pending_with_credit(
            &scan.snapshots,
            &mut index.claude_usage_family_pending,
            &scan.census_window_end,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            Some(&mut budget),
        )?;
        Ok(Some(ClaudeNativeObservations {
            counts,
            census_window_end: window,
            index_generation: index.generation,
        }))
    }

    /// Both real selected-save callers use the same moving credit. Recovery
    /// never requests new optional capacity after a body has been offered.
    pub(crate) fn restore_selected_paid(
        &mut self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
    ) -> Result<bool, crate::source_rotation::LocalRefusal> {
        self.require_paid_recovery()?;
        let Some(fallback) = self.fallback.as_mut() else {
            return Ok(false);
        };
        #[cfg(test)]
        let result = {
            let reserved = self
                .reservation
                .as_ref()
                .expect("checked moving recovery")
                .recovery_bytes_for_test();
            // Selected recovery is synchronous on this thread: map/set/path
            // updates spawn no work and transfer no allocations to a worker.
            // Audit its born-in-scope peak, excluding unrelated parallel tests.
            let (result, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
                fallback.restore_selected(index, previous)
            });
            assert!(
                allocation.requested_peak_with_overlap <= reserved,
                "actual selected recovery peak{} exceeds prepaid{}",
                allocation.requested_peak_with_overlap,
                reserved
            );
            eprintln!("native selected recovery: actual_requested_peak={} prepaid_peak={reserved} same_moving_credit=true", allocation.requested_peak_with_overlap);
            result
        };
        #[cfg(not(test))]
        let result = fallback.restore_selected(index, previous);
        result.map_err(crate::source_rotation::LocalRefusal)?;
        Ok(true)
    }

    pub(crate) fn require_paid_recovery(&self) -> Result<(), crate::source_rotation::LocalRefusal> {
        if self.fallback.is_some()
            && !self
                .reservation
                .as_ref()
                .is_some_and(crate::source_rotation::PaidReservation::recovery_is_reserved)
        {
            return Err(crate::source_rotation::LocalRefusal(
                "native comparison selected recovery lost its moving reservation",
            ));
        }
        Ok(())
    }

    pub(crate) fn attach_reservation(
        &mut self,
        reservation: Option<crate::source_rotation::PaidReservation>,
    ) {
        assert!(self.reservation.is_none(), "one moving native reservation");
        self.reservation = reservation;
    }
    /// A revoked optimization permit still cannot discard an actual completed
    /// native census. No negative certificate or native correction is created.
    pub(crate) fn base(terminal: Option<Box<TerminalTraversal>>) -> Option<Self> {
        Some(Self {
            reservation: None,
            window: None,
            fallback: None,
            native_plans: BTreeMap::new(),
            pending_corrections: Vec::new(),
            target_charges: TargetChargeReceipts::default(),
            native_terminal: Some(terminal?.into_native_census()),
        })
    }
    pub(super) fn native_window(&self) -> Option<&str> {
        self.native_terminal
            .as_ref()
            .map(|terminal| terminal.census_window_end.as_str())
            .or_else(|| {
                self.fallback
                    .as_ref()
                    .and_then(|fallback| fallback.terminal.as_deref())
                    .map(|terminal| terminal.traversal.census_window_end.as_str())
            })
    }
    /// Normal completion has already dropped the traversal graph, retaining
    /// only its moving window receipt through the native fold. A fallback has
    /// a different lifetime: both selected-save seams need its full traversal.
    pub(crate) fn retire_native_fold_owner(&mut self) {
        drop(self.native_terminal.take());
    }
    #[cfg(test)]
    pub(crate) fn ordinary_terminal_retained_for_test(&self) -> bool {
        self.native_terminal.is_some()
    }
    #[cfg(test)]
    pub(crate) fn native_correction_count_for_test(&self) -> usize {
        self.window
            .as_ref()
            .map_or(0, |window| window.native_corrections.len())
    }
    #[cfg(test)]
    pub(crate) fn pending_native_correction_count_for_test(&self) -> usize {
        self.pending_corrections.len()
    }

    /// Select candidates before the canonical finalizer removes semantic no-ops.
    /// No fingerprint/body projection is computed here. The ordinary finalizer
    /// supplies its exact current witness through observe_native_correction.
    pub(crate) fn prepare_native_corrections(
        &mut self,
        scan: &SourceScanResult,
        previous: &ScanIndex,
        disposition: &ClaudeUsageAuthorityDisposition,
    ) {
        self.pending_corrections.clear();
        let Some(window) = self.window.as_ref() else {
            return;
        };
        for item in &scan.snapshots {
            let Some(plan) = self.native_plans.get(&item.source_session_id) else {
                continue;
            };
            if item.usage_accounting_contract.as_deref()
                != Some("session_exclusive_reported_usage:v1")
                || disposition
                    .quarantined_source_session_ids
                    .contains(&item.source_session_id)
                || window.correction_forbidden_roots.contains(&plan.root)
            {
                continue;
            }
            let Some(pending) = scan.pending_finalization.iter().find(|pending| {
                pending.parse_complete
                    && pending.parsed_snapshot_count == 1
                    && !pending.sampled_audit_verified
                    && pending.source_file_fingerprint == plan.revision
                    && item.source_file_fingerprint.as_ref() == Some(&plan.revision)
                    && claude_index_path_member_ref(Path::new(&pending.index_key)).is_some_and(
                        |member| {
                            member.root == plan.root
                                && member.matches_member(&item.source_session_id)
                        },
                    )
                    && previous
                        .files
                        .get(&pending.index_key)
                        .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            }) else {
                continue;
            };
            if window.correction_revoked_keys.contains(&pending.index_key) {
                continue;
            }
            let strings = pending
                .index_key
                .len()
                .checked_add(plan.root.len())
                .and_then(|bytes| bytes.checked_add(plan.proof.len()))
                .and_then(|bytes| bytes.checked_add(plan.revision.len()));
            let growth = if self.pending_corrections.len() == self.pending_corrections.capacity() {
                self.pending_corrections
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(std::mem::size_of::<PendingNativeCorrection>()))
            } else {
                Some(0)
            };
            let Some(owned) = prepay_correction_metadata(
                &mut self.reservation,
                strings.and_then(|bytes| bytes.checked_add(growth?)),
            ) else {
                continue;
            };
            if self.pending_corrections.try_reserve_exact(1).is_err() {
                continue;
            }
            self.pending_corrections.push(PendingNativeCorrection {
                key: pending.index_key.clone(),
                plan: NativePlan {
                    root: plan.root.clone(),
                    proof: plan.proof.clone(),
                    revision: plan.revision.clone(),
                },
                fingerprint: String::new(),
                body_witness: String::new(),
            });
            if !retain_correction_metadata(&mut self.reservation, owned) {
                self.pending_corrections.clear();
                return;
            }
        }
    }

    /// Observe the existing finalizer projection, after its semantic hash was
    /// recomputed. Repeated canonical checks must agree; a mismatch revokes this
    /// optional candidate. No additional serialization or alternate body exists.
    pub(crate) fn observe_native_correction(&mut self, item: &SnapshotItem, body_witness: &str) {
        let reservation = &mut self.reservation;
        self.pending_corrections.retain_mut(|candidate| {
            if candidate.plan.revision != item.source_file_fingerprint.as_deref().unwrap_or("")
                || !claude_index_path_member_ref(Path::new(&candidate.key)).is_some_and(
                    |identity| {
                        identity.root == candidate.plan.root
                            && identity.matches_member(&item.source_session_id)
                    },
                )
            {
                return true;
            }
            if candidate.fingerprint.is_empty() && candidate.body_witness.is_empty() {
                let Some(owned) = prepay_correction_metadata(
                    reservation,
                    item.snapshot_fingerprint
                        .len()
                        .checked_add(body_witness.len()),
                ) else {
                    return false;
                };
                candidate.fingerprint = item.snapshot_fingerprint.clone();
                candidate.body_witness = body_witness.to_owned();
                retain_correction_metadata(reservation, owned)
            } else {
                candidate.fingerprint == item.snapshot_fingerprint
                    && candidate.body_witness == body_witness
            }
        });
    }

    /// Data-level primitive fixture has no physical source finalizer. The
    /// actual pipeline and settlement regressions use its observer seam.
    #[cfg(test)]
    pub(crate) fn capture_native_corrections(
        &mut self,
        scan: &mut SourceScanResult,
        previous: &ScanIndex,
        disposition: &ClaudeUsageAuthorityDisposition,
        body_witness: impl Fn(&SnapshotItem) -> String,
    ) {
        self.prepare_native_corrections(scan, previous, disposition);
        for item in &mut scan.snapshots {
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            self.observe_native_correction(item, &body_witness(item));
        }
    }

    /// Called only after the actual normal selected save succeeds. Partial,
    /// shed, error and pending-ACK paths never call this minting seam.
    pub(crate) fn note_native_corrections_after_save(
        &mut self,
        index: &ScanIndex,
        previous: &ScanIndex,
        // None is refused/unknown; false permits ONLY the bound accepted no-op.
        acknowledged: impl Fn(&str, &str) -> Option<bool>,
    ) -> crate::local_resource_diagnostics::NativeMint {
        let Some(window) = self.window.as_mut() else {
            return Default::default();
        };
        let mut diagnostic = crate::local_resource_diagnostics::NativeMint {
            window_available: true,
            candidates: self.pending_corrections.len(),
            ..Default::default()
        };
        for candidate in self.pending_corrections.drain(..) {
            if candidate.fingerprint.is_empty() || candidate.body_witness.is_empty() {
                continue; // No canonical finalizer projection was observed.
            }
            let Some(exact_ack) = acknowledged(&candidate.fingerprint, &candidate.body_witness)
            else {
                continue;
            };
            if window
                .correction_forbidden_roots
                .contains(&candidate.plan.root)
                || window.correction_revoked_keys.contains(&candidate.key)
            {
                continue;
            }
            let Some(entry) = index.files.get(&candidate.key) else {
                continue;
            };
            let Some(selected_fingerprint) = entry.last_snapshot_fingerprint.as_ref() else {
                continue;
            };
            let Some(selected_body_witness) = entry.last_upload_body_witness.as_ref() else {
                continue;
            };
            let exact_noop = !previous
                .quarantined_snapshot_fingerprints
                .contains_key(&candidate.fingerprint)
                && previous
                    .accepted_snapshot_fingerprints
                    .contains(&candidate.fingerprint)
                && previous
                    .file_snapshot_fingerprints
                    .get(&candidate.key)
                    .is_some_and(|fps| fps.len() == 1 && fps.contains(&candidate.fingerprint))
                && previous.files.get(&candidate.key).is_some_and(|old| {
                    old.last_snapshot_fingerprint.as_ref() == Some(selected_fingerprint)
                        && old.last_upload_body_witness.as_ref() == Some(selected_body_witness)
                });
            if !exact_ack && !exact_noop {
                continue;
            }
            let growth = window.native_corrections.growth_peak();
            let Some(owned) = prepay_correction_metadata(
                &mut self.reservation,
                selected_fingerprint
                    .len()
                    .checked_add(selected_body_witness.len())
                    .and_then(|bytes| bytes.checked_add(growth?)),
            ) else {
                continue;
            };
            let receipt = NativeCorrection {
                root: candidate.plan.root,
                proof: candidate.plan.proof,
                revision: candidate.plan.revision,
                fingerprint: candidate.fingerprint,
                body_witness: candidate.body_witness,
                selected_fingerprint: selected_fingerprint.clone(),
                selected_body_witness: selected_body_witness.clone(),
            };
            if receipt.current(&candidate.key, index) {
                window.native_corrections.insert(candidate.key, receipt);
                diagnostic.insertions = diagnostic.insertions.saturating_add(1);
                if !retain_correction_metadata(&mut self.reservation, owned) {
                    window.native_corrections.clear();
                    break;
                }
            }
        }
        self.native_plans.clear();
        diagnostic.receipts_after_mint = window.native_corrections.len();
        diagnostic
    }
}

pub(crate) struct SelectedFallback {
    withheld_sources: BTreeSet<String>,
    withheld_keys: BTreeSet<String>,
    targets: Vec<CandidateFile>,
    census_window_end: String,
    terminal: Option<Box<TerminalTraversal>>,
}

impl Controller {
    /// Price the existing constructor's new nodes, copied plan strings and
    /// selected-key workspace before it consumes the controller. Retained
    /// input and output overlap use this same reservation, not a finish pool.
    pub(crate) fn complete_paid(
        self,
        scan: &SourceScanResult,
        terminal: Option<Box<TerminalTraversal>>,
        current: bool,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> Result<Completion, crate::source_rotation::LocalRefusal> {
        use crate::heap_layout_bound::{self, Counter};
        let refuse = || {
            crate::source_rotation::LocalRefusal(
                "native comparison completion metadata cannot be prepaid before source offer",
            )
        };
        let plan = (|| {
            let paid = credit.as_mut()?;
            let occupied = paid.allocated();
            let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
            // This includes all moved certificates and the frozen input graph
            // while output metadata is constructed. No input copy is made.
            cost.add(heap_layout_bound::completed_bound(&self, usize::MAX)?)?;
            if let Some(terminal) = terminal.as_ref() {
                cost.add(heap_layout_bound::completed_bound(terminal, usize::MAX)?)?;
            }
            let plans = self
                .qualification
                .families
                .values()
                .try_fold(0usize, |n, f| n.checked_add(f.prior_native.len()))?;
            heap_layout_bound::tree_nodes::<String, NativePlan>(plans, &mut cost)?;
            for (root, family) in &self.qualification.families {
                for (member, prior) in &family.prior_native {
                    cost.add(member.len())?;
                    cost.add(root.len())?;
                    cost.add(family.proof.len())?;
                    cost.add(prior.revision.len())?;
                }
            }
            // into_window moves existing leaves into a compact buffer; its
            // old and replacement buffers overlap during geometric growth.
            restore_vec_peak::<(String, WindowRoot)>(self.qualification.families.len(), &mut cost)?;
            cost.add(
                std::mem::size_of::<WindowEligibility>()
                    .checked_add(std::mem::align_of::<WindowEligibility>())?,
            )?;
            cost.add(scan.census_window_end.len())?;
            cost.add(TargetChargeReceipts::construction_peak(
                scan,
                self.ordinary_body_frontier,
            )?)?;
            let pending = scan.pending_finalization.len();
            heap_layout_bound::tree_nodes::<String, ()>(pending, &mut cost)?; // withheld keys
            heap_layout_bound::tree_nodes::<String, ()>(pending, &mut cost)?; // resolved sources
            for entry in &scan.pending_finalization {
                // Stored key + canonical root/member conversion workspace.
                // Each field is a substring of the UTF-8 index path; the
                // canonical formatted member may use old+new buffers too.
                cost.add(entry.index_key.len().checked_mul(6)?)?;
            }
            let extra_sources = self
                .qualification
                .pending
                .values()
                .try_fold(0usize, |n, p| n.checked_add(p.sources.len()))?;
            heap_layout_bound::tree_nodes::<String, ()>(extra_sources, &mut cost)?;
            let targets = self.acquisition.known_rearm_candidates.len().checked_add(
                self.qualification
                    .pending
                    .values()
                    .try_fold(0usize, |n, p| n.checked_add(p.candidates.len()))?,
            )?;
            restore_vec_peak::<CandidateFile>(targets, &mut cost)?;
            let peak = occupied.checked_add(cost.bytes)?;
            paid.grow_for(peak).then_some((occupied, peak))
        })();
        let (occupied, prepaid) = plan.ok_or_else(refuse)?;
        #[cfg(test)]
        let result = {
            // complete() is synchronous on this thread (no spawn, channel or
            // pool) and consumes pre-existing state: born-in-scope accounting
            // charged to this thread only, so parallel tests cannot inflate it.
            let (result, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
                self.complete(scan, terminal, current)
            });
            assert!(
                allocation.requested_peak_with_overlap <= prepaid - occupied,
                "completion construction exceeds its same-owner prepayment"
            );
            eprintln!("native completion metadata: actual_requested_peak={} prepaid_extra={} no_input_clone=true same_moving_credit=true", allocation.requested_peak_with_overlap, prepaid - occupied);
            result
        };
        #[cfg(not(test))]
        let result = self.complete(scan, terminal, current);
        #[cfg(not(test))]
        let _ = prepaid;
        let completion = result.map_err(crate::source_rotation::LocalRefusal)?;
        let owned = heap_layout_bound::completed_bound(&completion, usize::MAX)
            .and_then(|bytes| occupied.checked_add(bytes))
            .ok_or_else(refuse)?;
        if !credit.as_mut().ok_or_else(refuse)?.record_allocated(owned) {
            return Err(refuse());
        }
        Ok(completion)
    }

    /// Consume pending plans even when a target could not be queued. Disabling
    /// the optimization must not discard the dependency that caused fallback.
    pub(crate) fn complete(
        mut self,
        scan: &SourceScanResult,
        terminal: Option<Box<TerminalTraversal>>,
        current: bool,
    ) -> Result<Completion, &'static str> {
        if !self.qualification.metadata_accounted() {
            return Err("native comparison metadata accounting is unknown");
        }
        if !current || self.failed || self.awaiting_targets {
            for (_, plan) in std::mem::take(&mut self.qualification.pending) {
                self.acquisition.unresolved_sources.extend(plan.sources);
                self.acquisition
                    .known_rearm_candidates
                    .extend(plan.candidates);
            }
        }
        // This is the last append-only producer boundary. Capture actual
        // source/revision ownership before withhold/filter/sort can shift it.
        // Multiple outputs share a receipt only at the SAME exact revision;
        // no-body targets add none, and dropped outputs grant no refund.
        let target_charges = TargetChargeReceipts::capture(scan, self.ordinary_body_frontier)?;
        let mut withheld_keys = BTreeSet::new();
        let mut resolved_sources = BTreeSet::new();
        for pending in &scan.pending_finalization {
            if let Some((_, member)) =
                claude_index_path_family_member(Path::new(&pending.index_key))
            {
                if self.acquisition.unresolved_sources.contains(&member) {
                    withheld_keys.insert(pending.index_key.clone());
                    resolved_sources.insert(member);
                }
            }
        }
        // A missing key cannot be represented by a fake hold or successful
        // checkpoint. Refuse before constructing or offering any new body.
        if !self
            .acquisition
            .unresolved_sources
            .is_subset(&resolved_sources)
        {
            return Err("native comparison fallback lacks an exact source key");
        }
        if !withheld_keys.is_empty() {
            return Ok(Completion {
                reservation: None,
                window: None,
                native_plans: BTreeMap::new(),
                pending_corrections: Vec::new(),
                target_charges,
                native_terminal: None,
                fallback: Some(SelectedFallback {
                    withheld_sources: self.acquisition.unresolved_sources,
                    withheld_keys,
                    targets: self.acquisition.known_rearm_candidates,
                    census_window_end: scan.census_window_end.clone(),
                    terminal,
                }),
            });
        }
        // Only fallback restoration needs the full graph. Retire it before
        // allocating plans/window metadata, moving its existing window string.
        let native_terminal = terminal.map(TerminalTraversal::into_native_census);
        let native_plans = self
            .qualification
            .families
            .iter()
            .flat_map(|(root, family)| {
                family.prior_native.iter().map(|(member, prior)| {
                    (
                        member.clone(),
                        NativePlan {
                            root: root.clone(),
                            proof: family.proof.clone(),
                            revision: prior.revision.clone(),
                        },
                    )
                })
            })
            .collect();
        Ok(Completion {
            reservation: None,
            native_plans,
            pending_corrections: Vec::new(),
            target_charges,
            native_terminal,
            window: if current {
                self.into_window(&scan.census_window_end)
            } else {
                None
            },
            fallback: None,
        })
    }
}

impl SelectedFallback {
    /// Price the existing selected-restore operations before any target is
    /// queued. All current native files are included, so later policy/ACK
    /// selection can only reduce the set. No index, key or body is cloned here.
    /// The unchanged normal/partial subset writer remains authoritative.
    pub(in crate::snapshots) fn recovery_peak<'a>(
        index: &ScanIndex,
        previous: &ScanIndex,
        pending: &[PendingIndexFinalization],
        targets: impl Iterator<Item = &'a CandidateFile> + Clone,
        paid: &mut crate::source_rotation::PaidReservation,
    ) -> Option<usize> {
        use crate::heap_layout_bound::{self, Counter};
        if !heap_layout_bound::layout_supported() {
            return None;
        }
        // The only planning allocation is the canonical root/member pair for
        // a prior marker lookup. Pay it before constructing either string.
        let lookup_scratch = pending
            .iter()
            .map(|read| read.index_key.len())
            .max()
            .unwrap_or(0)
            .checked_mul(2)?;
        if !paid.grow_for(paid.allocated().checked_add(lookup_scratch)?) {
            return None;
        }
        let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
        let traversal = index.traversal.as_ref()?;
        // A terminal checkpoint may have to outlive ordinary collection until
        // selected recovery. It moves, but its extended lifetime is not free.
        cost.add(heap_layout_bound::completed_bound(
            traversal,
            crate::source_rotation::PARKED_BUDGET,
        )?)?;
        let target_count = targets.clone().count();
        let keys = pending.len().checked_add(target_count)?;
        let mut affected = pending.len();
        let mut maximum_key = 0usize;
        for read in pending {
            let key = &read.index_key;
            maximum_key = maximum_key.max(key.len());
            cost.add(key.len())?;
            // The current final group/entity SHA may be replaced by policy.
            // Its 64-byte digest is copied into the temporary affected set.
            cost.add(64)?;
            let current = index.file_snapshot_fingerprints.get(key);
            affected = affected.checked_add(current.map_or(1, |fps| fps.len().max(1)))?;
            if let Some(fps) = current {
                for fp in fps {
                    cost.add(fp.capacity().max(64))?;
                }
            } else {
                cost.add(64)?;
            }
            if let Some(entry) = previous.files.get(key) {
                restore_tree_insert_peak::<String, ScanIndexEntry>(
                    index.files.len().checked_add(keys)?,
                    1,
                    &mut cost,
                )?;
                cost.add(key.len())?;
                cost.add(heap_layout_bound::completed_bound(
                    entry,
                    crate::source_rotation::PARKED_BUDGET,
                )?)?;
            }
            if let Some(fps) = previous.file_snapshot_fingerprints.get(key) {
                restore_tree_insert_peak::<String, BTreeSet<String>>(
                    index.file_snapshot_fingerprints.len().checked_add(keys)?,
                    1,
                    &mut cost,
                )?;
                cost.add(key.len())?;
                cost.add(heap_layout_bound::completed_bound(
                    fps,
                    crate::source_rotation::PARKED_BUDGET,
                )?)?;
            }
            // Exact prior entity set plus the prior group digest are the only
            // old accepted/activity entries the restore can insert.
            for fp in previous
                .file_snapshot_fingerprints
                .get(key)
                .into_iter()
                .flatten()
                .chain(
                    previous
                        .files
                        .get(key)
                        .and_then(|entry| entry.last_snapshot_fingerprint.as_ref()),
                )
            {
                if let Some(activity) = previous.snapshot_activity_at.get(fp) {
                    restore_tree_insert_peak::<String, Option<String>>(
                        index.snapshot_activity_at.len().checked_add(keys)?,
                        1,
                        &mut cost,
                    )?;
                    cost.add(fp.len())?;
                    cost.add(heap_layout_bound::completed_bound(
                        activity,
                        crate::source_rotation::PARKED_BUDGET,
                    )?)?;
                }
                if previous.accepted_snapshot_fingerprints.contains(fp) {
                    restore_tree_insert_peak::<String, ()>(
                        index
                            .accepted_snapshot_fingerprints
                            .len()
                            .checked_add(keys)?,
                        1,
                        &mut cost,
                    )?;
                    cost.add(fp.len())?;
                }
            }
            if previous.confirmed_empty_files.contains(key) {
                restore_tree_insert_peak::<String, ()>(
                    index.confirmed_empty_files.len().checked_add(keys)?,
                    1,
                    &mut cost,
                )?;
                cost.add(key.len())?;
            }
            if let Some(value) = previous.terminal_jsonl_dispositions.get(key) {
                restore_tree_insert_peak::<String, TerminalJsonlDisposition>(
                    index.terminal_jsonl_dispositions.len().checked_add(keys)?,
                    1,
                    &mut cost,
                )?;
                cost.add(key.len())?;
                cost.add(heap_layout_bound::completed_bound(
                    value,
                    crate::source_rotation::PARKED_BUDGET,
                )?)?;
            }
            if let Some(identity) = claude_index_path_member_ref(Path::new(key)) {
                let (_, member) = identity.into_owned();
                if let Some(value) = previous.claude_owned_start_census.get(&member) {
                    restore_tree_insert_peak::<String, ClaudeOwnedStartCensusWitness>(
                        index.claude_owned_start_census.len().checked_add(keys)?,
                        1,
                        &mut cost,
                    )?;
                    cost.add(key.len())?; // root/member construction and moved key
                    cost.add(heap_layout_bound::completed_bound(
                        value,
                        crate::source_rotation::PARKED_BUDGET,
                    )?)?;
                }
            }
        }
        heap_layout_bound::tree_nodes::<String, ()>(affected, &mut cost)?;
        for target in targets {
            let path = target.path.to_str()?;
            maximum_key = maximum_key.max(path.len());
            // New priority path/root and dedup key; source candidates stay
            // owned while these copies are built.
            cost.add(target.path.capacity())?;
            cost.add(target.scan_root.capacity())?;
            cost.add(path.len())?;
        }
        heap_layout_bound::tree_nodes::<String, ()>(keys, &mut cost)?;
        for read in pending {
            let path = Path::new(&read.index_key);
            let root = traversal
                .scan_roots
                .iter()
                .filter(|root| path.starts_with(root))
                .max_by_key(|root| root.components().count())?;
            cost.add(read.index_key.len())?;
            cost.add(root.capacity())?;
        }
        for path in &traversal.pending_candidates {
            maximum_key = maximum_key.max(path.path.to_str()?.len());
        }
        cost.add(maximum_key)?; // one retain/dedup lookup key at a time
        cost.add(lookup_scratch)?;
        restore_vec_peak::<ScanTraversalPath>(
            keys.checked_add(traversal.pending_candidates.len())?,
            &mut cost,
        )?;
        // Preserve #585's paired empty-map rollback. The existing helper runs
        // over all confirmed-empty keys; charge possible current-pass pairs
        // under correction roots too, without modifying their state/rules.
        if index.claude_authority_proof_correction_pending() {
            let revision = index
                .claude_usage_authority_quarantine
                .values()
                .flat_map(|record| record.member_source_file_fingerprints.values())
                .chain(
                    previous
                        .claude_usage_authority_quarantine
                        .values()
                        .flat_map(|record| record.member_source_file_fingerprints.values()),
                )
                .map(String::len)
                .max()
                .unwrap_or(0)
                .max(64);
            let mut advances = 0usize;
            let mut identity_scratch = index
                .confirmed_empty_files
                .iter()
                .map(String::len)
                .max()
                .unwrap_or(0)
                .checked_mul(2)?;
            for key in index.files.keys() {
                let Some(identity) = claude_index_path_member_ref(Path::new(key)) else {
                    continue;
                };
                identity_scratch = identity_scratch.max(key.len().checked_mul(2)?);
                if !index
                    .claude_usage_authority_quarantine
                    .get(identity.root)
                    .is_some_and(|record| record.proof_correction.is_some())
                {
                    continue;
                }
                advances = advances.checked_add(1)?;
                cost.add(identity.root.len())?;
                cost.add(key.len())?; // member <= canonical path length
                cost.add(key.len())?; // key
                cost.add(revision)?;
                cost.add(revision)?; // previous map value, if any
            }
            cost.add(identity_scratch)?;
            restore_vec_peak::<ClaudeEmptyMapAdvance>(advances, &mut cost)?;
        }
        Some(cost.bytes)
    }

    /// Called only after raw native observations have been recorded. A
    /// deferred file cannot be finalized as an empty or semantic-no-op file.
    pub(crate) fn withhold(&self, scan: &mut SourceScanResult) {
        eprintln!("local snapshot comparison deferred: reason=native_comparison_unavailable sources={} target_files={}; prior accepted bodies unchanged", self.withheld_sources.len(), self.targets.len());
        scan.snapshots
            .retain(|item| !self.withheld_sources.contains(&item.source_session_id));
    }

    pub(crate) fn after_native_fold(&self, scan: &mut SourceScanResult, index: &mut ScanIndex) {
        scan.pending_finalization
            .retain(|pending| !self.withheld_keys.contains(&pending.index_key));
        scan.census_complete = false;
        index.mark_bounded_sweep_unsettled();
    }

    /// Restore only selected B/C facts. Queue known A first and B/C after A in
    /// the SAME traversal. A terminal traversal is moved, never reconstructed
    /// from a scratch index or duplicated into SourceScanResult::clone.
    pub(crate) fn restore_selected(
        &mut self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
    ) -> Result<(), &'static str> {
        if !index.persistence_available() || !previous.persistence_available() {
            index.retain_persistence_baseline_from(previous);
            return Err("scan_index_map_unavailable");
        }

        let empty_advances = index.claude_empty_map_advances(previous);
        let mut affected_fingerprints = BTreeSet::new();
        for key in &self.withheld_keys {
            if let Some(entry) = index.files.get(key) {
                affected_fingerprints.extend(entry.last_snapshot_fingerprint.iter().cloned());
            }
            affected_fingerprints.extend(
                index
                    .file_snapshot_fingerprints
                    .remove(key)
                    .unwrap_or_default(),
            );
            match previous.files.get(key) {
                Some(entry) => {
                    index.files.insert(key.clone(), entry.clone());
                }
                None => {
                    index.files.remove(key);
                }
            }
            if let Some(fps) = previous.file_snapshot_fingerprints.get(key) {
                index
                    .file_snapshot_fingerprints
                    .insert(key.clone(), fps.clone());
                for fp in fps {
                    if let Some(activity) = previous.snapshot_activity_at.get(fp) {
                        index
                            .snapshot_activity_at
                            .insert(fp.clone(), activity.clone());
                    }
                    if previous.accepted_snapshot_fingerprints.contains(fp) {
                        index.accepted_snapshot_fingerprints.insert(fp.clone());
                    }
                }
            }
            if let Some(fp) = previous
                .files
                .get(key)
                .and_then(|entry| entry.last_snapshot_fingerprint.as_ref())
            {
                if let Some(activity) = previous.snapshot_activity_at.get(fp) {
                    index
                        .snapshot_activity_at
                        .insert(fp.clone(), activity.clone());
                }
                if previous.accepted_snapshot_fingerprints.contains(fp) {
                    index.accepted_snapshot_fingerprints.insert(fp.clone());
                }
            }
            if previous.confirmed_empty_files.contains(key) {
                index.confirmed_empty_files.insert(key.clone());
            } else {
                index.confirmed_empty_files.remove(key);
            }
            match previous.terminal_jsonl_dispositions.get(key) {
                Some(value) => {
                    index
                        .terminal_jsonl_dispositions
                        .insert(key.clone(), value.clone());
                }
                None => {
                    index.terminal_jsonl_dispositions.remove(key);
                }
            }
            // Slice D1: fail closed, never a record of either revision. The
            // first-seen birth of the same physical object stays (an in-place
            // stub every reader treats as no record; nothing is allocated).
            index.claude_request_census.invalidate_keeping_birth(key);
            if let Some((_, member)) = claude_index_path_family_member(Path::new(key)) {
                match previous.claude_owned_start_census.get(&member) {
                    Some(value) => {
                        index
                            .claude_owned_start_census
                            .insert(member, value.clone());
                    }
                    None => {
                        index.claude_owned_start_census.remove(&member);
                    }
                }
            }
        }
        index.restore_claude_empty_map_advances(empty_advances);
        for current in index.current_snapshot_fingerprint_refs() {
            affected_fingerprints.remove(current);
        }
        for fp in affected_fingerprints {
            index.accepted_snapshot_fingerprints.remove(&fp);
            index.snapshot_activity_at.remove(&fp);
        }
        if index.traversal.is_none() {
            index.traversal = self.terminal.take().map(|terminal| terminal.traversal);
        }
        let traversal = index
            .traversal
            .as_mut()
            .ok_or("native comparison lost its traversal")?;
        if traversal.census_window_end != self.census_window_end
            || traversal.context_fingerprint.is_empty()
        {
            return Err("native comparison traversal context changed");
        }
        // Only paths already observed in this frozen window may be requeued.
        // A missing path remains debt; a later native read decides disappearance.
        let mut priority = VecDeque::new();
        let mut keys = BTreeSet::new();
        for path in self
            .targets
            .iter()
            .map(|target| target.path.as_path())
            .chain(self.withheld_keys.iter().map(Path::new))
        {
            let key = local_index_key(path);
            if !keys.insert(key.clone()) {
                continue;
            }
            if !traversal.observed_index_keys.contains(&key) {
                return Err("native comparison recovery path was not observed in this window");
            }
            let root = traversal
                .scan_roots
                .iter()
                .filter(|root| path.starts_with(root))
                .max_by_key(|root| root.components().count())
                .ok_or("native comparison recovery path left its roots")?;
            priority.push_back(ScanTraversalPath {
                scan_root: root.clone(),
                path: path.to_path_buf(),
                census_member: true,
                watcher_hint: false,
            });
        }
        traversal
            .pending_candidates
            .retain(|candidate| !keys.contains(&local_index_key(&candidate.path)));
        priority.append(&mut traversal.pending_candidates);
        traversal.pending_candidates = priority;
        for target in &self.targets {
            if let Some(entry) = index.files.get_mut(&local_index_key(&target.path)) {
                entry.source_file_fingerprint.clear();
            }
        }
        index.mark_bounded_sweep_unsettled();
        Ok(())
    }
}

/// Existing Rust1.88/1.95 B=6 insertion can split at most one node per level
/// plus a new root. Charge the existing full-node upper bound for every such
/// allocation; never weaken the ordinary layout/version/visit guards.
pub(super) fn restore_tree_insert_peak<K, V>(
    maximum_entries: usize,
    operations: usize,
    cost: &mut crate::heap_layout_bound::Counter,
) -> Option<()> {
    if operations == 0 {
        return Some(());
    }
    let mut levels = 1usize;
    let mut width = 1usize;
    while width <= maximum_entries {
        width = width.checked_mul(6)?;
        levels = levels.checked_add(1)?;
    }
    crate::heap_layout_bound::tree_nodes::<K, V>(
        levels.checked_add(1)?.checked_mul(operations)?,
        cost,
    )
}

/// New push/append buffer and its preceding growth buffer may overlap. This
/// is a construction plan for the existing pinned Vec/VecDeque operations.
fn restore_vec_peak<T>(length: usize, cost: &mut crate::heap_layout_bound::Counter) -> Option<()> {
    if length == 0 {
        return Some(());
    }
    let capacity = length.max(4).checked_next_power_of_two()?;
    cost.add(
        capacity
            .checked_add(capacity / 2)?
            .checked_mul(std::mem::size_of::<T>())?,
    )
}

crate::heap_layout_bound::fields!(Completion; reservation, window, fallback, native_plans, pending_corrections, target_charges, native_terminal);
crate::heap_layout_bound::fields!(NativePlan; root, proof, revision);
crate::heap_layout_bound::fields!(NativeCorrection; root, proof, revision, fingerprint, body_witness, selected_fingerprint, selected_body_witness);
crate::heap_layout_bound::fields!(PendingNativeCorrection; key, plan, fingerprint, body_witness);
crate::heap_layout_bound::fields!(SelectedFallback; withheld_sources, withheld_keys, targets, census_window_end, terminal);

crate::heap_layout_bound::fields!(TargetChargeReceipts; revisions);
