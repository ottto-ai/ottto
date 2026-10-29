//! A Codex file group as one job (P2). A pre-job boot identifies the members,
//! reads their headers (the parent's `read_header_bytes`, called as-is),
//! plans the canonical order (§a.3) and, for legacy-shape groups, probes each
//! member to its first native record. The job then replays every member in
//! canonical order through ONE native parser and accumulator, swapping only
//! the reader per member, while `StreamProof` checks the replay in the same
//! pass. A group larger than the singleton page budget is a multi-member
//! cursor job (`codex_cursor`): sealed members are read to EOF with strict
//! identity, the live (last) member through its frozen-extent certificate.
//! Terminal proof refusals are settleable residue (outcome R); open/read
//! failures, line loss, receipts, owner and creator conflicts stay strict.
use super::*;
use sampled_scan::codex_cursor::{self as cursor, DisclosureTargets, OpenStamp};

/// A legacy-shape member's probe reads at most this many bytes looking for
/// its first native record. Past it, or past the boot's probe allowance, the
/// group keeps chronological order and the counter chain decides
/// (`probe_bound`); a refusal then is strict `ProbeBudgetOrder` (R1-M1).
const PROBE_BYTES: usize = 1024 * 1024;

/// The ONE accumulator creation point for group replay (§k.4): the group's
/// counting state is configured here, once, from every member's evidence
/// (#603 `configure_group_once`). Only the reader is swapped per member, so
/// no member reconfigures it. The legacy tee (`legacy_tee`) stays
/// unconfigured: it is baseline evidence, not a second counted stream.
#[allow(clippy::too_many_arguments)]
pub(in crate::snapshots) fn new_group_parser(
    file: File,
    member: &CandidateFile,
    metadata: &CodexTitleMetadata,
    traces: Option<Arc<CodexTurnTraceMap>>,
    ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    artifacts: bool,
    context_curve: bool,
    evidence: codex_counting_version::AckEvidence,
) -> Result<OwnedJsonlParser> {
    refuse_compressed_codex(
        Some(&member.path),
        None,
        CodexZstCause::GroupReadUnsupported,
    )?;
    let mut parser = OwnedJsonlParser::new(
        file,
        &member.path,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(metadata),
        traces,
        ledgers,
        artifacts,
        context_curve,
    )?;
    codex_counting_version::configure_group_once(&mut parser.accumulator, evidence);
    Ok(parser)
}

#[cfg(test)]
thread_local! {
    static TEST_V2: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests only: replay groups as V2 counting (§k.3) while cutover is None.
#[cfg(test)]
pub(in crate::snapshots) fn with_test_v2<T>(run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_V2.with(|v2| v2.set(false));
        }
    }
    TEST_V2.with(|v2| v2.set(true));
    let _reset = Reset;
    run()
}

/// The replay counts under V2 (§k.3): the accumulator's own decision, made
/// on the session's first owned record (false before it and while the
/// cutover is None).
pub(in crate::snapshots) fn group_counting_is_v2(accumulator: &SnapshotAccumulator) -> bool {
    #[cfg(test)]
    if TEST_V2.with(std::cell::Cell::get) {
        return true;
    }
    accumulator.codex_counting_v2()
}

/// The group job's logical key: home, owner and the sorted member keys. A
/// new or vanished member is a different job (memo, fence and slot keys).
pub(in crate::snapshots) fn job_key(group: &Group) -> String {
    let mut keys = group
        .members
        .iter()
        .map(|member| local_index_key(&member.path))
        .collect::<Vec<_>>();
    keys.sort();
    let mut parts = vec![
        "codex_group_job:v1".to_owned(),
        local_index_key(&group.home),
        group.owner.clone(),
    ];
    parts.extend(keys);
    sha256_hex_owned(&parts)
}

/// The settleable disclosure of one member of a refused group (outcome R).
pub(in crate::snapshots) fn refusal_disclosure(owner: &str) -> cursor::Disclosure {
    cursor::Disclosure {
        reason: cursor::DebtReason::HeldTerminal,
        cause: ownership::GROUP,
        ownership_incomplete_file_count: 1,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: vec![owner.to_owned()],
        diagnostic_reason: FileReason::OwnershipIncomplete,
        parsed_snapshot_count: 0,
        held: cursor::HeldCounts::default(),
        parent_ref: None,
        parent_unresolvable: None,
    }
}

/// The strict debt a parked `ProbeBudgetOrder` group discloses again
/// (round 3): never settleable, the owner held.
fn probe_order_disclosure(owner: &str) -> cursor::Disclosure {
    cursor::Disclosure {
        reason: cursor::DebtReason::ProbeBudgetOrder,
        cause: ownership::GROUP,
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: vec![owner.to_owned()],
        diagnostic_reason: FileReason::NotParsedThisCycle,
        parsed_snapshot_count: 0,
        held: cursor::HeldCounts::default(),
        parent_ref: None,
        parent_unresolvable: None,
    }
}

/// Every member's prior body is kept by a terminal disclosure.
fn previous_body(index: &ScanIndex, member: &CandidateFile) -> (Option<String>, Option<String>) {
    let keep = !index
        .effective_upload_body_witness_revision_requires_adoption(&local_index_key(&member.path));
    (
        keep.then(|| index.last_snapshot_fingerprint(member))
            .flatten(),
        keep.then(|| index.last_upload_body_witness(member))
            .flatten(),
    )
}

/// The one terminal writer, once per member.
pub(in crate::snapshots) fn disclose_members(
    disclosure: &cursor::Disclosure,
    members: &[CandidateFile],
    index: &mut ScanIndex,
    mut targets: DisclosureTargets<'_>,
) {
    for member in members {
        let previous = previous_body(index, member);
        cursor::disclose_terminal_codex_debt(
            disclosure,
            member,
            previous,
            index,
            targets.reborrow(),
        );
    }
}

/// A genuine open/read failure, line loss, receipt, owner or creator
/// conflict: strict, exactly as before P2.
pub(in crate::snapshots) fn disclose_strict(
    owner: &str,
    members: &[CandidateFile],
    targets: DisclosureTargets<'_>,
) {
    targets.census.ownership_incomplete_file_count += members.len();
    targets.census.causes.add(ownership::GROUP, members.len());
    targets
        .census
        .record_unreadable(UnreadableCause::AliasParser, 1);
    targets
        .residue_index_keys
        .extend(members.iter().map(|member| local_index_key(&member.path)));
    targets.residue_blocked_session_ids.insert(owner.to_owned());
    targets
        .codex_state_only_blocked_session_ids
        .insert(owner.to_owned());
}

/// How one boot step ended.
pub(in crate::snapshots) enum Boot {
    Pending,
    /// Every member is unchanged and joined under this exact member set.
    Unchanged,
    Strict,
    /// A header-derived refusal: terminal debt, decided at no replay cost.
    Refused(JoinRefusal),
    Ready,
}

/// Pre-job group state; one unit of work per scan step.
pub(in crate::snapshots) struct GroupBoot {
    pub(in crate::snapshots) group: Group,
    pub(in crate::snapshots) key: String,
    identified: usize,
    stamps: Vec<OpenStamp>,
    wake_identities: BTreeMap<String, String>,
    headers: Vec<MemberHeader>,
    plan: Option<GroupPlan>,
    probes: Vec<Option<Tokens>>,
    probed: usize,
    ordered: bool,
    /// The unchanged and receipt checks passed: the boot reads from here.
    admitted: bool,
    pub(in crate::snapshots) probe_bound: bool,
    /// A probe was cut by `PROBE_BYTES` itself, not by the allowance: the
    /// fallback order is the same every generation (round 3).
    probe_limit_bound: bool,
    /// This boot runs on a page of its own (round 3, `ProbeBudgetOrder`).
    pub(in crate::snapshots) own_page: bool,
    /// Probe bytes this boot may still read (R2-N2): the page's remaining
    /// singleton budget, set by the scanner before each step.
    probe_allowance: u64,
    charge: u64,
    previous_receipts: BTreeMap<String, (Option<AppliedTierReceipt>, bool)>,
    receipt_scope: String,
    legacy_expected: BTreeMap<String, String>,
    evidence: codex_counting_version::AckEvidence,
}
crate::heap_layout_bound::fields!(GroupBoot; group, key, identified, stamps, wake_identities, headers, plan,
    probes, probed, ordered, admitted, probe_bound, probe_limit_bound, own_page, probe_allowance,
    charge, previous_receipts, receipt_scope, legacy_expected, evidence);

impl GroupBoot {
    pub(in crate::snapshots) fn new(group: Group, index: &ScanIndex) -> Self {
        let receipt_scope = index
            .active_upload_context_fingerprint
            .clone()
            .unwrap_or_default();
        let mut previous_receipts = BTreeMap::new();
        let mut legacy_expected = BTreeMap::new();
        for member in &group.members {
            let key = local_index_key(&member.path);
            if let Some(entry) = index.files.get(&key) {
                if entry.codex_joined_member_set.is_none()
                    && entry.codex_captured_joined_member_set.is_none()
                    && entry.codex_applied_tier_receipt.is_none()
                    && entry.codex_captured_tier_receipt.is_none()
                {
                    if let Some(expected) = &entry.last_snapshot_fingerprint {
                        legacy_expected.insert(key.clone(), expected.clone());
                    }
                }
                previous_receipts.insert(key, receipt_state(Some(entry)));
            }
        }
        let evidence = codex_counting_version::members_evidence(&group.members, index);
        Self {
            key: job_key(&group),
            group,
            identified: 0,
            stamps: Vec::new(),
            wake_identities: BTreeMap::new(),
            headers: Vec::new(),
            plan: None,
            probes: Vec::new(),
            probed: 0,
            ordered: false,
            admitted: false,
            probe_bound: false,
            probe_limit_bound: false,
            own_page: false,
            probe_allowance: u64::MAX,
            charge: 0,
            previous_receipts,
            receipt_scope,
            legacy_expected,
            evidence,
        }
    }

    /// Header and probe bytes read since the last call.
    pub(in crate::snapshots) fn take_charge(&mut self) -> u64 {
        std::mem::take(&mut self.charge)
    }

    /// Every member is identified and the group is neither unchanged nor
    /// receipt-strict, and no header was read yet: the boot's first read
    /// (round 3, R2-M1: the cursor-slot check sits here).
    pub(in crate::snapshots) fn awaits_read(&self) -> bool {
        self.admitted && self.headers.is_empty()
    }

    /// Cap this boot's remaining probe reads (R2-N2). A probe cut by it ends
    /// probing like `PROBE_BYTES`: the group keeps chronological order, and
    /// a refusal in that order is `ProbeBudgetOrder` (strict, R1-M1).
    pub(in crate::snapshots) fn allow_probe_bytes(&mut self, bytes: u64) {
        self.probe_allowance = bytes;
    }

    /// Sum of the identified member lengths: the read this group needs.
    pub(in crate::snapshots) fn expected_bytes(&self) -> u64 {
        self.group
            .members
            .iter()
            .fold(0u64, |sum, member| sum.saturating_add(member.size_bytes))
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn step(
        &mut self,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
        index: &ScanIndex,
    ) -> Boot {
        self.step_with_cache(attribution, index, None)
    }

    pub(in crate::snapshots) fn step_with_cache(
        &mut self,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
        index: &ScanIndex,
        cache: Option<&sampled_scan::SharedCache>,
    ) -> Boot {
        let n = self.group.members.len();
        if self.identified < n {
            return self.identify(attribution, index, cache);
        }
        if !self.admitted {
            if self.unchanged_joined(index) {
                return Boot::Unchanged;
            }
            if !self.receipts_valid() {
                return Boot::Strict;
            }
            self.admitted = true;
            return Boot::Pending;
        }
        if self.headers.len() < n {
            let member = &self.group.members[self.headers.len()];
            let Ok((bytes, _, read, _)) = read_header_bytes(member) else {
                return Boot::Strict;
            };
            self.charge = self.charge.saturating_add(read as u64);
            return match MemberHeader::parse(&bytes, member) {
                Some(header) => {
                    self.headers.push(header);
                    Boot::Pending
                }
                // The inventory parsed this header: a failure now is a
                // change under the read (TOCTOU), never proof debt (R1-M3).
                None => Boot::Strict,
            };
        }
        if self.plan.is_none() {
            let keys = self
                .group
                .members
                .iter()
                .map(|member| local_index_key(&member.path))
                .collect::<Vec<_>>();
            return match plan_group(&self.headers, &keys) {
                Ok(plan) => {
                    self.ordered = plan.ordinal;
                    self.plan = Some(plan);
                    self.probes = vec![None; n];
                    Boot::Pending
                }
                Err(reason) => Boot::Refused(reason),
            };
        }
        if !self.ordered {
            if self.probed < n && !self.probe_bound {
                return self.probe(self.probed);
            }
            if !self.probe_bound {
                let chronological = &self.plan.as_ref().expect("planned").order;
                match order_by_probes(chronological, &self.probes) {
                    Ok(order) => self.plan.as_mut().expect("planned").order = order,
                    Err(reason) => return Boot::Refused(reason),
                }
            }
            self.ordered = true;
        }
        Boot::Ready
    }

    fn identify(
        &mut self,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
        index: &ScanIndex,
        cache: Option<&sampled_scan::SharedCache>,
    ) -> Boot {
        let i = self.identified;
        let mut candidate = self.group.members[i].clone();
        if let Some(context) = attribution {
            let workers = vec![self.group.owner.clone()];
            match context.prepare_launch_step(&workers) {
                Ok(false) => return Boot::Pending,
                Err(()) => return Boot::Strict,
                Ok(true) => {}
            }
            if let Some(witness) = context.launch_witness(&workers) {
                candidate.source_file_fingerprint = sha256_hex(&[
                    "launcher_worker_context:v1",
                    &candidate.source_file_fingerprint,
                    &witness,
                ]);
            }
        }
        let mut census = ScanCensus::default();
        let Some((opened, file)) = open_and_identify_scan_candidate_with_rescue(
            SnapshotSource::Codex,
            candidate,
            &mut census,
            None,
            0,
            // The entry's stored ctime lets a ctime-only change keep the
            // stored fingerprint (fresh samples hashed, no re-read).
            &index.files,
            false,
            cache,
        ) else {
            return Boot::Strict;
        };
        let Ok(stamp) = OpenStamp::capture(&file) else {
            return Boot::Strict;
        };
        let identity = cache.map_or_else(
            || opened.opened_object_identity.clone(),
            |cache| cache.retained_stamp_identity(&opened, &opened.opened_object_identity),
        );
        self.wake_identities
            .insert(local_index_key(&opened.path), identity);
        self.group.members[i] = opened;
        self.stamps.push(stamp);
        self.identified += 1;
        Boot::Pending
    }

    fn unchanged_joined(&self, index: &ScanIndex) -> bool {
        let witness = member_set_witness(&self.group.members);
        self.group.members.iter().all(|member| {
            index.candidate_decision(member) == CandidateDecision::Skip
                && index
                    .files
                    .get(&local_index_key(&member.path))
                    .is_some_and(|entry| {
                        entry.codex_joined_member_set.as_deref() == Some(witness.as_str())
                            && !index.effective_upload_body_witness_revision_requires_adoption(
                                &local_index_key(&member.path),
                            )
                    })
        })
    }

    fn receipts_valid(&self) -> bool {
        self.group.members.iter().all(|member| {
            self.previous_receipts
                .get(&local_index_key(&member.path))
                .map_or(true, |(receipt, required)| {
                    (!required || receipt.is_some())
                        && receipt.as_ref().map_or(true, |receipt| {
                            receipt.version == RECEIPT_VERSION
                                && receipt.derivation == SnapshotSource::Codex.parser_version()
                                && receipt.scope == self.receipt_scope
                                && receipt.tiers.len() <= MAX_APPLIED_TIERS
                        })
                })
        })
    }

    /// One legacy-shape member up to its first native record, bounded.
    fn probe(&mut self, i: usize) -> Boot {
        let member = &self.group.members[i];
        if refuse_compressed_codex(
            Some(&member.path),
            None,
            CodexZstCause::GroupProbeUnsupported,
        )
        .is_err()
        {
            return Boot::Strict;
        }
        let cap = self.probe_allowance.min(PROBE_BYTES as u64);
        let result = (|| -> std::io::Result<(Option<Tokens>, bool, u64)> {
            let file = open_candidate_beneath_root(member)?;
            let mut reader = BufReader::with_capacity(64 * 1024, file.take(cap + 1));
            let mut line = Vec::new();
            let mut read = 0u64;
            loop {
                line.clear();
                let n = reader.read_until(b'\n', &mut line)?;
                read = read.saturating_add(n as u64);
                if n == 0 || line.last() != Some(&b'\n') {
                    // EOF (or a withheld tail) before any native record.
                    return Ok((None, read > cap, read));
                }
                #[cfg(test)]
                codex_zst_refusal_tests::jsonl_parse_attempted();
                if let Some(before) = serde_json::from_slice::<Value>(&line)
                    .ok()
                    .as_ref()
                    .and_then(probe_before)
                {
                    return Ok((Some(before), false, read));
                }
            }
        })();
        let Ok((before, bound, read)) = result else {
            return Boot::Strict;
        };
        self.probe_limit_bound |= bound && cap == PROBE_BYTES as u64;
        self.charge = self.charge.saturating_add(read);
        self.probe_allowance = self.probe_allowance.saturating_sub(read);
        self.probes[i] = before;
        self.probe_bound |= bound;
        self.probed += 1;
        Boot::Pending
    }

    fn canonical_order(&self) -> &[usize] {
        self.plan.as_ref().map_or(&[], |plan| plan.order.as_slice())
    }

    /// The canonical last member and its boot stamp: the only member that can
    /// be live, the memo's stamp and witness anchor.
    pub(in crate::snapshots) fn live(&self) -> Option<(&CandidateFile, &OpenStamp)> {
        let last = *self.canonical_order().last()?;
        Some((&self.group.members[last], self.stamps.get(last)?))
    }

    /// The group's reduction dependencies with every sealed member's opened
    /// identity (R2-H1): a parked record wakes on a sealed member's change,
    /// never on the live member's growth.
    pub(in crate::snapshots) fn dependencies(&self, codex: &CodexTitleMetadata) -> Option<String> {
        let (live, _) = self.live()?;
        Some(cursor::group_dependencies(
            &self.group.members,
            &live.path,
            codex,
            |member| self.wake_identity(member),
        ))
    }

    /// M-1 `scope_job` with the group's wake dependencies (§d.4).
    pub(in crate::snapshots) fn memo_digest(
        &self,
        index: &ScanIndex,
        codex: &CodexTitleMetadata,
    ) -> Option<String> {
        let order = self.canonical_order();
        let (_, live) = self.live()?;
        Some(cursor::group_memo_digest(
            &self.group.owner,
            &order
                .iter()
                .map(|i| &self.group.members[*i])
                .collect::<Vec<_>>(),
            live,
            &order
                .iter()
                .map(|i| self.headers.get(*i).map_or("", MemberHeader::digest))
                .collect::<Vec<_>>(),
            index,
            codex,
            &self.receipt_scope,
            |member| self.wake_identity(member),
        ))
    }

    fn wake_identity(&self, member: &CandidateFile) -> String {
        self.wake_identities
            .get(&local_index_key(&member.path))
            .unwrap_or(&member.opened_object_identity)
            .clone()
    }

    /// Open the first canonical member and build the job.
    pub(in crate::snapshots) fn into_job(
        self,
        inputs: JobInputs<'_>,
    ) -> std::result::Result<Box<OwnedActiveFile>, GroupEnd> {
        let memo_digest = self.memo_digest(inputs.index, inputs.metadata);
        let dependencies = self.dependencies(inputs.metadata);
        let Self {
            group,
            key,
            stamps,
            headers,
            plan,
            probe_bound,
            probe_limit_bound,
            own_page,
            previous_receipts,
            receipt_scope,
            legacy_expected,
            evidence,
            ..
        } = self;
        let plan = plan.ok_or(GroupEnd::Strict)?;
        let members = plan
            .order
            .iter()
            .map(|i| group.members[*i].clone())
            .collect::<Vec<_>>();
        let stamps = plan
            .order
            .iter()
            .filter_map(|i| stamps.get(*i).cloned())
            .collect::<Vec<_>>();
        let digests = plan
            .order
            .iter()
            .map(|i| {
                headers
                    .get(*i)
                    .map_or_else(String::new, |h| h.digest().to_owned())
            })
            .collect::<Vec<_>>();
        let (Some(first), Some(last)) = (members.first().cloned(), members.last().cloned()) else {
            return Err(GroupEnd::Strict);
        };
        if stamps.len() != members.len() {
            return Err(GroupEnd::Strict);
        }
        let mut opened = first.clone();
        let file = open_member_file(&mut opened)?;
        if opened.opened_object_identity != first.opened_object_identity {
            return Err(GroupEnd::Changed);
        }
        let tee = legacy_tee(
            &legacy_expected,
            &first,
            &file,
            inputs.metadata,
            inputs.traces.clone(),
            inputs.ledgers.clone(),
            inputs.artifacts,
            inputs.context_curve,
        )?;
        let mut parser = new_group_parser(
            file,
            &first,
            inputs.metadata,
            inputs.traces,
            inputs.ledgers,
            inputs.artifacts,
            inputs.context_curve,
            evidence,
        )
        .map_err(|_| GroupEnd::Strict)?;
        let v2 = group_counting_is_v2(&parser.accumulator);
        let mut join = Box::new(StreamProof::new(group.owner.clone(), v2, plan.plans));
        join.begin_member(0);
        let previous = previous_receipts
            .get(&local_index_key(&first.path))
            .cloned()
            .unwrap_or_default();
        let mut replay = TierReplay::new(previous.0, previous.1, receipt_scope.clone());
        replay.join = Some(join);
        parser.accumulator.codex_tier_replay = Some(replay);
        let index = inputs.index;
        Ok(Box::new(OwnedActiveFile {
            comparison_target: false,
            sampling: None,
            previous_snapshot_fingerprint: index.last_snapshot_fingerprint(&last),
            previous_upload_body_witness: index.last_upload_body_witness(&last),
            projection_adoption_required: index
                .effective_upload_body_witness_revision_requires_adoption(&local_index_key(
                    &last.path,
                )),
            source_file_fingerprint: last.source_file_fingerprint.clone(),
            candidate: first,
            decision: CandidateDecision::Parse,
            parser,
            aliases: members.clone(),
            applied_receipts: BTreeMap::new(),
            cursor: None,
            charged_bytes: 0,
            hold_offset: None,
            // U1a-2a: a group job is never a side read.
            side_origin: None,
            group: Some(Box::new(GroupJob {
                key,
                owner: group.owner,
                home: group.home,
                members,
                stamps,
                digests,
                current: 0,
                finished: false,
                previous_receipts,
                receipt_scope,
                legacy_expected,
                tee,
                legacy_baselines: Vec::new(),
                lines: (0, 0),
                charge: 0,
                probe_bound,
                probe_limit_bound,
                own_page,
                dependencies,
                memo_digest,
                scope: cursor::group_scope(index),
                walked: None,
                consumed_before: 0,
            })),
        }))
    }
}

/// Scan facts a group job is built with.
pub(in crate::snapshots) struct JobInputs<'a> {
    pub(in crate::snapshots) metadata: &'a CodexTitleMetadata,
    pub(in crate::snapshots) traces: Option<Arc<CodexTurnTraceMap>>,
    pub(in crate::snapshots) ledgers:
        Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    pub(in crate::snapshots) artifacts: bool,
    pub(in crate::snapshots) context_curve: bool,
    pub(in crate::snapshots) index: &'a ScanIndex,
}

fn open_member_file(member: &mut CandidateFile) -> std::result::Result<File, GroupEnd> {
    refuse_compressed_codex(
        Some(&member.path),
        None,
        CodexZstCause::GroupReadUnsupported,
    )
    .map_err(|_| GroupEnd::Strict)?;
    match open_candidate_file(SnapshotSource::Codex, member) {
        Ok(file) => Ok(file),
        // The member vanished or was renamed: membership changed.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(GroupEnd::Changed),
        Err(_) => Err(GroupEnd::Strict),
    }
}

/// A member that was indexed as its own file before it joined keeps its
/// legacy pricing baseline: the same records, applied to a second parser in
/// the same pass (no extra read), finished like the pre-P2 proof parser.
#[allow(clippy::too_many_arguments)]
fn legacy_tee(
    legacy_expected: &BTreeMap<String, String>,
    member: &CandidateFile,
    file: &File,
    metadata: &CodexTitleMetadata,
    traces: Option<Arc<CodexTurnTraceMap>>,
    ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    artifacts: bool,
    context_curve: bool,
) -> std::result::Result<Option<Box<OwnedJsonlParser>>, GroupEnd> {
    refuse_compressed_codex(
        Some(&member.path),
        None,
        CodexZstCause::GroupReadUnsupported,
    )
    .map_err(|_| GroupEnd::Strict)?;
    if !legacy_expected.contains_key(&local_index_key(&member.path)) {
        return Ok(None);
    }
    let clone = file.try_clone().map_err(|_| GroupEnd::Strict)?;
    OwnedJsonlParser::new(
        clone,
        &member.path,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(metadata),
        traces,
        ledgers,
        artifacts,
        context_curve,
    )
    .map(|tee| Some(Box::new(tee)))
    .map_err(|_| GroupEnd::Strict)
}

/// The running group job, carried by its `OwnedActiveFile`.
pub(in crate::snapshots) struct GroupJob {
    pub(in crate::snapshots) key: String,
    pub(in crate::snapshots) owner: String,
    pub(in crate::snapshots) home: PathBuf,
    /// Canonical order; the last member is the only one that can be live.
    pub(in crate::snapshots) members: Vec<CandidateFile>,
    /// Boot stamps of the members' opened objects, canonical order.
    pub(in crate::snapshots) stamps: Vec<OpenStamp>,
    digests: Vec<String>,
    pub(in crate::snapshots) current: usize,
    finished: bool,
    previous_receipts: BTreeMap<String, (Option<AppliedTierReceipt>, bool)>,
    receipt_scope: String,
    legacy_expected: BTreeMap<String, String>,
    tee: Option<Box<OwnedJsonlParser>>,
    legacy_baselines: Vec<LegacyBaseline>,
    /// Physical and parsed line counts of the completed members.
    lines: (usize, usize),
    charge: u64,
    pub(in crate::snapshots) probe_bound: bool,
    probe_limit_bound: bool,
    own_page: bool,
    /// `GroupBoot::dependencies`: a parked `ProbeBudgetOrder` record's wake
    /// inputs (round 3).
    pub(in crate::snapshots) dependencies: Option<String>,
    pub(in crate::snapshots) memo_digest: Option<String>,
    /// `cursor::group_scope` at job start (§p, R1-M1): every resume and the
    /// emission compare it with the current index.
    pub(in crate::snapshots) scope: String,
    /// The last walked copy-budget charge of a group read without the
    /// cursor (E3, R2-M2; a cursor job keeps it in its `JobMeta`).
    pub(in crate::snapshots) walked: Option<(usize, u64, usize)>,
    /// Bytes the completed members' readers consumed: E3 measures a group's
    /// input cumulatively, so a member swap needs no walk (R2-L3).
    pub(in crate::snapshots) consumed_before: u64,
}
crate::heap_layout_bound::fields!(GroupJob; key, owner, home, members, stamps, digests, current,
    finished, previous_receipts, receipt_scope, legacy_expected, tee, legacy_baselines, lines,
    charge, probe_bound, probe_limit_bound, own_page, dependencies, memo_digest, scope, walked,
    consumed_before);

impl GroupJob {
    /// A legacy tee takes every consumed record too (E3, R2-N5).
    pub(in crate::snapshots) fn has_tee(&self) -> bool {
        self.tee.is_some()
    }

    pub(in crate::snapshots) fn take_legacy_baselines(&mut self) -> Vec<LegacyBaseline> {
        std::mem::take(&mut self.legacy_baselines)
    }

    /// The tee's live source-wide inputs (a paused job holds none).
    pub(in crate::snapshots) fn take_tee_inputs(
        &mut self,
    ) -> Option<sampled_jsonl::LiveReductionInputs> {
        self.tee
            .as_mut()
            .map(|tee| tee.take_live_reduction_inputs())
    }

    pub(in crate::snapshots) fn restore_tee_inputs(
        &mut self,
        inputs: Option<sampled_jsonl::LiveReductionInputs>,
    ) {
        if let (Some(tee), Some(inputs)) = (self.tee.as_mut(), inputs) {
            tee.restore_live_reduction_inputs(inputs);
        }
    }

    pub(in crate::snapshots) fn reinstall_tee_inputs(
        &mut self,
        traces: Option<Arc<CodexTurnTraceMap>>,
        parents: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    ) {
        if let Some(tee) = self.tee.as_mut() {
            tee.accumulator.codex_turn_traces = traces;
            tee.accumulator.codex_parent_ownership_ledgers = parents;
        }
    }
}

/// Bytes the group consumed outside the current reader (completed members,
/// header rechecks) since the last call.
pub(in crate::snapshots) fn take_charge(active: &mut OwnedActiveFile) -> u64 {
    active
        .group
        .as_mut()
        .map_or(0, |group| std::mem::take(&mut group.charge))
}

/// How a group job ended without completing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum GroupEnd {
    /// Terminal proof debt (outcome R) at canonical `position`; `offset` is
    /// the end of the last complete record read in that member.
    /// `at_eof` marks a refusal raised by the member-end proof, where the
    /// reader stopped at its read limit; a mid-stream refusal stops it early.
    Refused {
        reason: JoinRefusal,
        position: usize,
        offset: u64,
        at_eof: bool,
    },
    /// Open/read failure, line loss, receipts, owner or creator conflict.
    Strict,
    /// A member changed or vanished: a necessary invalidation.
    Changed,
    /// The live member's acquisition evidence is unavailable this page (K9).
    Unavailable,
}

pub(in crate::snapshots) enum GroupStep {
    /// The replay advanced; `Ok(true)` once the last member's EOF is proven.
    Read(Result<bool>),
    End(GroupEnd),
}

/// Scan facts one group step needs.
pub(in crate::snapshots) struct StepInputs<'a> {
    pub(in crate::snapshots) metadata: &'a CodexTitleMetadata,
    pub(in crate::snapshots) attribution:
        Option<&'a crate::session_attribution::SessionAttributionContext>,
    pub(in crate::snapshots) artifacts: bool,
    pub(in crate::snapshots) context_curve: bool,
    /// The live member's acquisition scope (cursor jobs), computed on demand.
    pub(in crate::snapshots) live_scope:
        &'a dyn Fn(&CandidateFile) -> Option<crate::transcript_acquisition::Scope>,
}

/// The reader skipped a line (malformed, invalid UTF-8 or over the line
/// cap) or failed: a refusal seen after that may be the loss's own effect
/// (an ordinal jump, a broken chain), so it is strict, never settleable
/// debt or a memo entry (R1-B1).
fn reader_lossy(parser: &OwnedJsonlParser) -> bool {
    !parser.reader.report.complete() || parser.reader.failure.is_some()
}

fn join_refusal(parser: &OwnedJsonlParser) -> Option<(JoinRefusal, usize)> {
    parser
        .accumulator
        .codex_tier_replay
        .as_ref()
        .and_then(|replay| replay.join.as_ref())
        .and_then(|join| join.refusal())
}

/// One physical line of the current member, or one member transition.
pub(in crate::snapshots) fn step_group(
    active: &mut OwnedActiveFile,
    inputs: &StepInputs<'_>,
) -> GroupStep {
    if active.group.as_ref().map_or(true, |group| group.finished) {
        return GroupStep::Read(Ok(true));
    }
    let offset = active.parser.reader.last_complete_line_end();
    if let Some(join) = active
        .parser
        .accumulator
        .codex_tier_replay
        .as_mut()
        .and_then(|replay| replay.join.as_deref_mut())
    {
        join.set_record_start(offset);
    }
    let stepped = {
        let OwnedActiveFile { parser, group, .. } = &mut *active;
        match group.as_mut().and_then(|group| group.tee.as_deref_mut()) {
            Some(tee) => parser.step_with_observer(|value| tee.tee_line(value)),
            None => parser.step(),
        }
    };
    let complete = match stepped {
        Ok(complete) => complete,
        Err(error) => return GroupStep::Read(Err(error)),
    };
    if let Some((reason, position)) = join_refusal(&active.parser) {
        if reader_lossy(&active.parser) {
            return GroupStep::End(GroupEnd::Strict);
        }
        return GroupStep::End(GroupEnd::Refused {
            reason,
            position,
            offset: active.parser.reader.last_complete_line_end(),
            at_eof: false,
        });
    }
    if !complete {
        return GroupStep::Read(Ok(false));
    }
    match member_eof(active, inputs) {
        Ok(done) => GroupStep::Read(Ok(done)),
        Err(end) => GroupStep::End(end),
    }
}

/// The current member reached its EOF: prove it, then open the next member
/// in the same step, or finish the group. `Ok(false)` also re-enters an EOF
/// whose launch lookup yields; nothing is consumed before that lookup.
fn member_eof(
    active: &mut OwnedActiveFile,
    inputs: &StepInputs<'_>,
) -> std::result::Result<bool, GroupEnd> {
    if reader_lossy(&active.parser) {
        return Err(GroupEnd::Strict);
    }
    let paged = active.cursor.is_some();
    let group = active.group.as_deref_mut().expect("group job");
    let position = group.current;
    let member = group.members[position].clone();
    let key = local_index_key(&member.path);
    let last = position + 1 == group.members.len();
    if let (Some(context), Some(tee)) = (inputs.attribution, group.tee.as_ref()) {
        let workers = tee
            .accumulator
            .source_session_id
            .as_ref()
            .map(|id| vec![resolve_codex_identity(id)])
            .unwrap_or_else(|| launch_workers_for_path(SnapshotSource::Codex, &member.path));
        // The legacy baseline below needs the lookup; park the finished
        // member until it is prepared.
        match context.prepare_launch_step(&workers) {
            Ok(false) => return Ok(false),
            Err(()) => return Err(GroupEnd::Strict),
            Ok(true) => {}
        }
    }
    // A cursor job's live member is fenced by its certificate; every other
    // member keeps exact identity at EOF.
    if !(last && paged) {
        match opened_object_identity(SnapshotSource::Codex, active.parser.reader.reader.get_mut()) {
            Ok(identity) if identity == member.opened_object_identity => {}
            Ok(_) => return Err(GroupEnd::Changed),
            Err(_) => return Err(GroupEnd::Strict),
        }
    }
    if last && paged {
        apply_live_eof_record(active);
    }
    let eof_applied = cursor::eof_applied(active);
    let end = active.parser.reader.consumed_bytes();
    let Some(mut replay) = active.parser.accumulator.codex_tier_replay.take() else {
        return Err(GroupEnd::Strict);
    };
    let mut join = replay.join.take().ok_or(GroupEnd::Strict)?;
    // The version is decided on the first owned record, after the proof
    // was built; the member-end rules follow it.
    join.decide_v2(group_counting_is_v2(&active.parser.accumulator));
    join.end_member(end);
    if last {
        join.finish_group();
    }
    if let Some((reason, position)) = join.refusal() {
        return Err(GroupEnd::Refused {
            reason,
            position,
            offset: active.parser.reader.last_complete_line_end(),
            at_eof: true,
        });
    }
    let receipt = replay.finish().map_err(|_| GroupEnd::Strict)?;
    // The variable records this member leaves in the job (round 4, L3).
    let mut retained = [
        crate::heap_layout_bound::completed_bound(&receipt, usize::MAX),
        crate::heap_layout_bound::completed_bound(&key, usize::MAX),
        Some(0),
    ];
    active.applied_receipts.insert(key.clone(), receipt);
    let report = active.parser.reader.report;
    let group = active.group.as_deref_mut().expect("group job");
    if let Some(mut tee) = group.tee.take() {
        let expected = group
            .legacy_expected
            .get(&key)
            .cloned()
            .ok_or(GroupEnd::Strict)?;
        tee.reader.finished = true;
        tee.reader.report = report;
        if last && paged && !eof_applied {
            // The live member's legacy baseline reads the same frozen prefix.
            tee.reader.sealed_prefix = active
                .cursor
                .as_ref()
                .map(|meta| cursor::frozen_grant(meta, end));
        }
        let parsed = (*tee)
            .finish(
                &member.opened_object_identity,
                &member.path,
                "1970-01-01T00:00:00Z",
                member.source_file_fingerprint.clone(),
                Some(inputs.metadata),
                None,
                inputs.attribution,
            )
            .map_err(|_| GroupEnd::Strict)?;
        if !parsed.complete() {
            return Err(GroupEnd::Strict);
        }
        let mut snapshots = parsed.snapshots;
        for snapshot in &mut snapshots {
            apply_codex_state_evidence(snapshot, inputs.metadata, &member.path);
        }
        let baseline = LegacyBaseline {
            owner: group.owner.clone(),
            index_key: key,
            expected,
            snapshots,
        };
        retained[2] = crate::heap_layout_bound::completed_bound(&baseline, usize::MAX);
        group.legacy_baselines.push(baseline);
    }
    group.lines.0 += report.physical_line_count;
    group.lines.1 += report.parsed_json_line_count;
    if last {
        // The existing single-file optional witness can be cleared on
        // conflict. A joined body must not reach account fallback through it.
        let owner = active
            .parser
            .accumulator
            .source_session_id
            .as_deref()
            .map(resolve_codex_identity);
        if active.parser.accumulator.codex_creator_evidence_conflicted
            || owner.as_deref() != Some(group.owner.as_str())
        {
            return Err(GroupEnd::Strict);
        }
        active.parser.reader.report.physical_line_count = group.lines.0;
        active.parser.reader.report.parsed_json_line_count = group.lines.1;
        group.finished = true;
        return Ok(true);
    }
    // The finished member's unread charge moves to the group before its
    // reader is replaced (`take_charge`).
    group.charge = group
        .charge
        .saturating_add(end.saturating_sub(active.charged_bytes));
    active.charged_bytes = 0;
    // E3: the swap's retained state is charged, not walked (round 4, L3).
    group.consumed_before = group
        .consumed_before
        .saturating_add(cursor::swap_charge(&retained));
    group.current += 1;
    open_member(active, join, inputs)?;
    Ok(false)
}

/// E1 for a paged group's live member (R2-N1), at its genuine unchanged
/// EOF only (`cursor::group_eof_record_due`): the withheld final record is
/// applied from the buffered bytes through the same line sink, the proof
/// and the legacy tee included, before the member's proof ends. The job
/// then gets no S12 grant (`finish_job`), so strict finish identity covers
/// the record. Without it, a quiescent live member ending in an
/// unterminated record would stage hourly audit debt and re-read the whole
/// group each time.
fn apply_live_eof_record(active: &mut OwnedActiveFile) {
    let Some(boot) = active
        .group
        .as_ref()
        .and_then(|group| group.stamps.last().cloned())
    else {
        return;
    };
    if !cursor::group_eof_record_due(active, &boot) {
        return;
    }
    let offset = active.parser.reader.last_complete_line_end();
    let applied = {
        let OwnedActiveFile { parser, group, .. } = &mut *active;
        if let Some(join) = parser
            .accumulator
            .codex_tier_replay
            .as_mut()
            .and_then(|replay| replay.join.as_deref_mut())
        {
            join.set_record_start(offset);
        }
        let mut tee = group.as_mut().and_then(|group| group.tee.as_deref_mut());
        parser.with_line_sink(
            |value| {
                if let Some(tee) = tee.as_mut() {
                    tee.tee_line(value);
                }
            },
            |reader, sink| reader.apply_sealed_fragment(sink),
        )
    };
    if applied {
        cursor::mark_eof_applied(active);
    }
}

/// Swap in the next canonical member's reader and its proof context.
fn open_member(
    active: &mut OwnedActiveFile,
    mut join: Box<StreamProof>,
    inputs: &StepInputs<'_>,
) -> std::result::Result<(), GroupEnd> {
    let paged = active.cursor.is_some();
    let group = active.group.as_deref_mut().expect("group job");
    let position = group.current;
    let member = group.members[position].clone();
    let boot = group
        .stamps
        .get(position)
        .cloned()
        .ok_or(GroupEnd::Strict)?;
    let last = position + 1 == group.members.len();
    let mut opened = member.clone();
    let file = open_member_file(&mut opened)?;
    if last && paged {
        // The live member may have grown since boot; its line 0 must not
        // have changed (TOCTOU), and its object is fenced below.
        let (bytes, _, read, _) = read_header_bytes(&member).map_err(|_| GroupEnd::Changed)?;
        group.charge = group.charge.saturating_add(read as u64);
        if format!("{:x}", Sha256::digest(&bytes)) != group.digests[position] {
            return Err(GroupEnd::Changed);
        }
    } else if opened.opened_object_identity != member.opened_object_identity {
        return Err(GroupEnd::Changed);
    }
    let tee = legacy_tee(
        &group.legacy_expected,
        &member,
        &file,
        inputs.metadata,
        active.parser.accumulator.codex_turn_traces.clone(),
        active
            .parser
            .accumulator
            .codex_parent_ownership_ledgers
            .clone(),
        inputs.artifacts,
        inputs.context_curve,
    )?;
    let previous = group
        .previous_receipts
        .get(&local_index_key(&member.path))
        .cloned()
        .unwrap_or_default();
    let receipt_scope = group.receipt_scope.clone();
    group.tee = tee;
    // E3 keeps counting across the swap (R2-N4, R2-L3): no walk per member.
    group.consumed_before = group
        .consumed_before
        .saturating_add(active.parser.reader.consumed_bytes());
    let parser = &mut active.parser;
    parser.reader = BoundedJsonlReader::new(OpenedInput::plain(file), jsonl_line_cap(), true);
    // Context inferred in one physical file must not price an unrelated
    // record at the beginning of another file.
    parser.accumulator.current_selector = SelectorCapture::default();
    parser.accumulator.latest_model = None;
    parser.accumulator.latest_reasoning_effort = None;
    parser.accumulator.latest_turn_id = None;
    if paged {
        let scope = if last {
            Some((inputs.live_scope)(&member).ok_or(GroupEnd::Unavailable)?)
        } else {
            None
        };
        cursor::arm_group_member(active, &boot, scope.as_ref())?;
    }
    join.begin_member(position);
    let mut replay = TierReplay::new(previous.0, previous.1, receipt_scope);
    replay.join = Some(join);
    active.parser.accumulator.codex_tier_replay = Some(replay);
    active.candidate = member;
    Ok(())
}

/// Where a group's end is recorded.
pub(in crate::snapshots) struct EndInputs<'a> {
    pub(in crate::snapshots) sampling: Option<&'a sampled_scan::Context>,
    pub(in crate::snapshots) index: &'a mut ScanIndex,
    pub(in crate::snapshots) targets: DisclosureTargets<'a>,
}

/// End a group job that did not complete. Terminal proof debt is disclosed
/// through the one writer for every member (outcome R) and memoized; an
/// append-curable refusal in the live member only while that member's stamp
/// is exactly unchanged (§d.4, R2-M1). The attempt is fenced for the
/// generation.
pub(in crate::snapshots) fn end_group(
    active: Box<OwnedActiveFile>,
    end: GroupEnd,
    lease: Option<cursor::CursorLease>,
    inputs: EndInputs<'_>,
) {
    let EndInputs {
        sampling,
        index,
        mut targets,
    } = inputs;
    let Some(group) = active.group.as_deref() else {
        return;
    };
    match end {
        // R1-M1: the chronological fallback order may itself break the
        // chain (a budget artifact, not a property of the files): strict,
        // never settleable or memoized, named for S11. Per-member reasons
        // (UI balance, shape) do not depend on the order.
        GroupEnd::Refused {
            reason: reason @ (JoinRefusal::Gap | JoinRefusal::Overlap),
            position,
            ..
        } if group.probe_bound => {
            if let Some(context) = sampling {
                context
                    .cache
                    .note_join_refusal(JoinRefusal::ProbeBudgetOrder);
                // Round 3 (R1-L1, R2-L2): converge under stable inputs. An
                // order the page's remaining singleton budget forced gets a
                // page of its own next; one `PROBE_BYTES` forced (or forced
                // again on its own page) is the same every generation, so it
                // parks like `JoinStateBound` until a member changes.
                if group.probe_limit_bound || group.own_page {
                    if let Some(stamp) = group.stamps.last() {
                        context.cache.park_group(
                            &group.key,
                            context.cache.retained_stamp(
                                &group.members.last().expect("live member").path,
                                stamp.clone(),
                            ),
                            group.dependencies.clone(),
                            probe_order_disclosure(&group.owner),
                            reason.append_curable() && position + 1 == group.members.len(),
                        );
                    }
                } else {
                    context
                        .cache
                        .request_group_own_page(&context.namespace, &group.key);
                }
            }
            // Round 4 (L1): the attempt ends like every terminal group end,
            // completing its rotation (waiter removed, served, fenced).
            if let Some(lease) = lease {
                cursor::end_group_lease(lease, &active);
            }
            disclose_strict(&group.owner, &group.members, targets.reborrow());
            cursor::dequeue_members(index, &group.members);
        }
        GroupEnd::Refused {
            reason,
            position,
            offset,
            at_eof,
        } => {
            let disclosure = refusal_disclosure(&group.owner);
            let live_failed = position + 1 == group.members.len();
            if let Some(context) = sampling {
                context.cache.note_join_refusal(reason);
                // §d.4: growth of the live member may cure this refusal, so
                // its entry matches only the exact recorded stamp: any
                // append or touch wakes it, an unchanged group is not re-read.
                let growth_may_cure = reason.append_curable() && live_failed;
                let held = active.parser.reader.reader.get_ref();
                let anchor = if live_failed {
                    // R1-H1: an exact-stamp entry never covers bytes the job
                    // did not read (growth past a paged cut): they may
                    // already cure it, so the next generation reads them.
                    // Round-3 R1-M1: only a refusal raised at the read limit
                    // can be cured by those bytes; a mid-stream refusal is
                    // fixed by records already read, and any append still
                    // misses the exact stamp.
                    OpenStamp::capture(held).ok().filter(|stamp| {
                        !growth_may_cure || !at_eof || stamp.extent() == cursor::read_end(&active)
                    })
                } else {
                    group.stamps.last().cloned()
                };
                // A refusal in the live member is witnessed at its refused
                // offset; one before any complete record is not memoized.
                let live = live_failed
                    .then(|| cursor::LiveWitness::read(&active.candidate.path, held, offset))
                    .flatten();
                if let (Some(digest), Some(stamp)) = (group.memo_digest.clone(), anchor) {
                    if !live_failed || live.is_some() {
                        context.cache.memo_record(
                            cursor::memo_key(&context.namespace, &group.key),
                            cursor::MemoEntry::new_group(
                                digest,
                                live,
                                context.cache.retained_stamp(
                                    &group.members.last().expect("live member").path,
                                    stamp,
                                ),
                                None,
                                None,
                                disclosure.clone(),
                            )
                            .growth_may_cure(growth_may_cure),
                        );
                    }
                }
                context.cache.group_attempted(
                    &context.namespace,
                    &group.key,
                    cursor::census_token(index).as_deref(),
                );
            }
            if let Some(lease) = lease {
                cursor::end_group_lease(lease, &active);
            }
            disclose_members(&disclosure, &group.members, index, targets.reborrow());
            cursor::dequeue_members(index, &group.members);
        }
        GroupEnd::Changed if lease.is_some() => {
            let lease = lease.expect("checked lease");
            let cache = &sampling.expect("a cursor job has a sampling context").cache;
            if let Some(disclosure) = cache.cursor_invalidate(lease, &active) {
                disclose_members(&disclosure, &group.members, index, targets.reborrow());
                cursor::dequeue_members(index, &group.members);
            }
            // Otherwise its members are still pending: a later page boots
            // the group again.
        }
        GroupEnd::Unavailable if lease.is_some() => {
            if let Some(lease) = lease {
                cursor::defer_group_lease(lease);
            }
        }
        GroupEnd::Strict | GroupEnd::Changed | GroupEnd::Unavailable => {
            if let Some(lease) = lease {
                lease.release();
            }
            disclose_strict(&group.owner, &group.members, targets.reborrow());
            cursor::dequeue_members(index, &group.members);
        }
    }
}

#[cfg(test)]
#[path = "group_job_tests.rs"]
mod tests;
