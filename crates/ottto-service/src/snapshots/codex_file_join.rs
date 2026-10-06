//! Local proof for joining physical Codex rollouts. Requested-tier selectors
//! retain the existing reader's meaning; response ownership is a separate fact.
use super::*;

pub(super) const MAX_MEMBERS: usize = 32;
pub(super) const MAX_RECORDS: usize = 50_000;
pub(super) const MAX_HEADER_BYTES: usize = 64 * 1024;

const MAX_HEADER_FILES: usize = 32_768;
const MAX_HEADER_READ_BYTES: usize = 32 * 1024 * 1024;
pub(super) const MAX_GROUP_BYTES: u64 = 256 * 1024 * 1024;

fn metadata_witness(metadata: &fs::Metadata) -> String {
    let mut digest = Sha256::new();
    digest.update(metadata.len().to_be_bytes());
    digest.update(
        metadata
            .modified()
            .ok()
            .and_then(unix_nanos)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    #[cfg(unix)]
    {
        digest.update(metadata.dev().to_be_bytes());
        digest.update(metadata.ino().to_be_bytes());
        digest.update(metadata.ctime().to_be_bytes());
        digest.update(metadata.ctime_nsec().to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

/// Membership is a directory-census fact. Persist this with the existing
/// traversal so a resumed page cannot certify a directory from another epoch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct DirectoryCensus {
    directories: BTreeMap<String, String>,
    stable: bool,
}
impl DirectoryCensus {
    pub(super) fn new() -> Self {
        Self {
            stable: true,
            ..Self::default()
        }
    }
    pub(super) fn observe(&mut self, path: &Path, before: &fs::Metadata) {
        let witness = metadata_witness(before);
        if self.directories.len() >= MAX_HEADER_FILES
            && !self.directories.contains_key(&local_index_key(path))
        {
            self.stable = false;
            return;
        }
        let after = fs::symlink_metadata(path).ok();
        self.stable &= after.as_ref().is_some_and(|after| {
            after.is_dir() && !after.file_type().is_symlink() && metadata_witness(after) == witness
        });
        if self
            .directories
            .insert(local_index_key(path), witness.clone())
            .is_some_and(|previous| previous != witness)
        {
            self.stable = false;
        }
    }
    pub(super) fn validate(&self, home: &Path) -> Result<()> {
        anyhow::ensure!(self.stable, "Codex joining directory census is unproved");
        let mut count = 0;
        for (path, witness) in &self.directories {
            if !Path::new(path).starts_with(home) {
                continue;
            }
            count += 1;
            let current = fs::symlink_metadata(path)?;
            anyhow::ensure!(
                current.is_dir()
                    && !current.file_type().is_symlink()
                    && metadata_witness(&current) == *witness,
                "Codex joining directory membership changed"
            );
        }
        anyhow::ensure!(count > 0, "Codex joining lacks an owning directory census");
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct HeaderWitness {
    pub(super) candidate: CandidateFile,
    pub(super) owner: String,
    pub(super) home: PathBuf,
    metadata: String,
}
pub(super) fn member_home(root: &Path) -> PathBuf {
    root.ancestors()
        .find(|path| {
            matches!(
                path.file_name().and_then(|value| value.to_str()),
                Some("sessions" | "archived_sessions")
            )
        })
        .and_then(Path::parent)
        .unwrap_or(root)
        .to_path_buf()
}
fn read_header(candidate: &CandidateFile) -> Result<(String, String, usize)> {
    let file = open_candidate_beneath_root(candidate)?;
    let before = file.metadata()?;
    anyhow::ensure!(before.is_file(), "Codex header is not a regular file");
    let mut reader = BufReader::with_capacity(1024, file.take((MAX_HEADER_BYTES + 1) as u64));
    let mut bytes = Vec::new();
    reader.read_until(b'\n', &mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_HEADER_BYTES && bytes.last() == Some(&b'\n'),
        "Codex header exceeds its read bound"
    );
    let value: Value = serde_json::from_slice(&bytes)?;
    let meta =
        codex_session_meta_payload(&value).context("Codex first record is not a owning header")?;
    let owner = resolve_codex_identity_option(codex_identity_at(meta, &["id"]))
        .context("Codex header lacks ownership")?;
    let after = reader.get_ref().get_ref().metadata()?;
    let witness = metadata_witness(&before);
    anyhow::ensure!(
        metadata_witness(&after) == witness,
        "Codex header changed while read"
    );
    // Include the bounded read-ahead in accounting, not only the header length.
    let read_bytes = (MAX_HEADER_BYTES + 1) - reader.get_ref().limit() as usize;
    Ok((owner, witness, read_bytes))
}

/// One small secure header read per existing native scan step. No transcript
/// or header Value is parked between steps.
#[derive(Clone, Debug)]
pub(super) struct HeaderInventory {
    roots: Vec<PathBuf>,
    pending: VecDeque<PathBuf>,
    pub(super) headers: Vec<HeaderWitness>,
    pub(super) directories: DirectoryCensus,
    pub(super) complete: bool,
    pub(super) read_bytes: usize,
}
impl HeaderInventory {
    pub(super) fn new(
        roots: &[PathBuf],
        paths: &BTreeSet<String>,
        directories: Option<&DirectoryCensus>,
    ) -> Self {
        Self {
            roots: roots.to_vec(),
            pending: paths
                .iter()
                .take(MAX_HEADER_FILES + 1)
                .map(PathBuf::from)
                .collect(),
            headers: Vec::new(),
            directories: directories.cloned().unwrap_or_default(),
            complete: paths.len() <= MAX_HEADER_FILES
                && directories.is_some_and(|value| value.stable),
            read_bytes: 0,
        }
    }
    pub(super) fn step(&mut self, metadata: &CodexTitleMetadata) -> bool {
        let Some(path) = self.pending.pop_front() else {
            return true;
        };
        if self.read_bytes >= MAX_HEADER_READ_BYTES || self.headers.len() >= MAX_HEADER_FILES {
            self.complete = false;
            self.pending.clear();
            return true;
        }
        let Some(scan_root) = self
            .roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
        else {
            self.complete = false;
            return false;
        };
        let result = (|| -> Result<HeaderWitness> {
            let stat = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                stat.is_file() && !stat.file_type().is_symlink(),
                "invalid Codex header member"
            );
            let seconds = stat.modified().ok().and_then(unix_seconds).unwrap_or(0);
            let mut candidate = CandidateFile {
                scan_root,
                path,
                size_bytes: stat.len(),
                modified_unix_seconds: seconds,
                modified_unix_nanos: stat
                    .modified()
                    .ok()
                    .and_then(unix_nanos)
                    .unwrap_or(seconds.saturating_mul(1_000_000_000)),
                source_file_fingerprint: String::new(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
            };
            prepare_owned_scan_candidate(
                SnapshotSource::Codex,
                &mut candidate,
                metadata,
                &ClaudeTitleMetadata::default(),
                None,
            );
            let (owner, witness, bytes) = read_header(&candidate)?;
            self.read_bytes = self.read_bytes.saturating_add(bytes);
            Ok(HeaderWitness {
                home: member_home(&candidate.scan_root),
                candidate,
                owner,
                metadata: witness,
            })
        })();
        match result {
            Ok(header) => self.headers.push(header),
            Err(_) => {
                self.complete = false;
                // A failed read may have consumed its whole bounded prefix.
                self.read_bytes = self.read_bytes.saturating_add(MAX_HEADER_BYTES + 1);
            }
        }
        if self.read_bytes > MAX_HEADER_READ_BYTES {
            self.complete = false;
        }
        false
    }
    pub(super) fn groups(&self) -> BTreeMap<String, Group> {
        let mut groups = BTreeMap::<String, Group>::new();
        for header in &self.headers {
            let key = sha256_hex(&[
                "codex_file_group:v1",
                &local_index_key(&header.home),
                &header.owner,
            ]);
            groups
                .entry(key)
                .or_insert_with(|| Group {
                    owner: header.owner.clone(),
                    home: header.home.clone(),
                    members: Vec::new(),
                })
                .members
                .push(header.candidate.clone());
        }
        groups
    }
    pub(super) fn validate_membership(&self, owner: &str, home: &Path) -> Result<()> {
        anyhow::ensure!(
            self.complete,
            "Codex joining header inventory is incomplete"
        );
        self.directories.validate(home)?;
        for header in &self.headers {
            if header.home != home {
                continue;
            }
            let stat = fs::symlink_metadata(&header.candidate.path)?;
            if metadata_witness(&stat) == header.metadata {
                continue;
            }
            let (current_owner, _, _) = read_header(&header.candidate)?;
            anyhow::ensure!(
                current_owner == header.owner || (current_owner != owner && header.owner != owner),
                "Codex joining header ownership changed"
            );
        }
        Ok(())
    }
}
crate::heap_layout_bound::fields!(DirectoryCensus; directories, stable);
crate::heap_layout_bound::fields!(HeaderWitness; candidate, owner, home, metadata);
crate::heap_layout_bound::fields!(HeaderInventory; roots, pending, headers, directories, complete, read_bytes);

#[derive(Clone, Debug)]
pub(super) struct Group {
    pub(super) owner: String,
    pub(super) home: PathBuf,
    pub(super) members: Vec<CandidateFile>,
}
#[derive(Clone, Debug)]
pub(super) struct Validation {
    pub(super) inventory: HeaderInventory,
    pub(super) groups: Vec<Group>,
}
impl Validation {
    pub(super) fn validate(&self, owners: &BTreeSet<String>) -> Result<()> {
        for group in &self.groups {
            if !owners.contains(&group.owner) {
                continue;
            }
            self.inventory
                .validate_membership(&group.owner, &group.home)?;
            for member in &group.members {
                let mut opened = member.clone();
                let _file = open_candidate_file(SnapshotSource::Codex, &mut opened)?;
                anyhow::ensure!(
                    opened.opened_object_identity == member.opened_object_identity,
                    "Codex joined member changed after replay"
                );
            }
        }
        Ok(())
    }
}
crate::heap_layout_bound::fields!(Group; owner, home, members);
crate::heap_layout_bound::fields!(Validation; inventory, groups);

pub(super) fn member_set_witness(members: &[CandidateFile]) -> String {
    let sorted = members
        .iter()
        .map(|member| {
            (
                local_index_key(&member.path),
                member.source_file_fingerprint.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut digest = Sha256::new();
    digest.update(b"codex_joined_member_set:v1\0");
    for (path, fingerprint) in sorted {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update(fingerprint.as_bytes());
    }
    format!("{:x}", digest.finalize())
}
#[derive(Clone, Debug)]
pub(crate) struct LegacyBaseline {
    pub(crate) owner: String,
    pub(crate) index_key: String,
    pub(crate) expected: String,
    pub(crate) snapshots: Vec<SnapshotItem>,
}
crate::heap_layout_bound::fields!(LegacyBaseline; owner, index_key, expected, snapshots);
const RECEIPT_VERSION: u16 = 1;
const MAX_APPLIED_TIERS: usize = 512;
pub(super) const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
/// Previous application evidence, not provider billing truth. Only hashes of
/// physical records/context and the applied priority provenance are retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedTierReceipt {
    version: u16,
    derivation: String,
    scope: String,
    records: usize,
    prefix_digest: String,
    tiers: BTreeMap<String, String>,
}
pub(super) fn deserialize_receipt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<AppliedTierReceipt>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    // A future/malformed local receipt must hold its file, rather than make
    // the ordinary index decoder discard every protected file as corruption.
    Ok(Some(serde_json::from_value(value).unwrap_or_else(|_| {
        AppliedTierReceipt {
            version: u16::MAX,
            derivation: String::new(),
            scope: String::new(),
            records: 0,
            prefix_digest: String::new(),
            tiers: BTreeMap::new(),
        }
    })))
}
impl AppliedTierReceipt {
    pub(super) fn retained_bytes(&self) -> usize {
        struct Bytes(usize);
        impl std::io::Write for Bytes {
            fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(value.len());
                Ok(value.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut bytes = Bytes(0);
        if serde_json::to_writer(&mut bytes, self).is_err() {
            return usize::MAX;
        }
        bytes.0
    }
    pub(super) fn covered_by(&self, previous: &Self) -> bool {
        self.version == previous.version
            && self.derivation == previous.derivation
            && self.scope == previous.scope
            && self
                .tiers
                .iter()
                .all(|(key, source)| previous.tiers.get(key) == Some(source))
    }
}
pub(super) fn receipt_state(entry: Option<&ScanIndexEntry>) -> (Option<AppliedTierReceipt>, bool) {
    let Some(entry) = entry else {
        return (None, false);
    };
    let missing = (entry.codex_captured_tier_receipt_required
        && entry.codex_captured_tier_receipt.is_none())
        || (entry.codex_applied_tier_receipt_required
            && entry.codex_applied_tier_receipt.is_none())
        || (entry.codex_captured_uncommitted && entry.codex_captured_tier_receipt.is_none());
    let required = missing
        || entry.codex_captured_tier_receipt_required
        || entry.codex_applied_tier_receipt_required;
    if missing {
        return (None, required);
    }
    (
        entry
            .codex_captured_tier_receipt
            .clone()
            .or_else(|| entry.codex_applied_tier_receipt.clone()),
        required,
    )
}
pub(super) struct TierReplay {
    previous: Option<AppliedTierReceipt>,
    digest: ContentDigest,
    records: usize,
    matched: BTreeSet<String>,
    tiers: BTreeMap<String, String>,
    scope: String,
    prefix_matched: bool,
    invalid: bool,
}
impl TierReplay {
    pub(super) fn new(previous: Option<AppliedTierReceipt>, required: bool, scope: String) -> Self {
        let invalid = previous.as_ref().is_some_and(|receipt| {
            receipt.version != RECEIPT_VERSION
                || receipt.derivation != SnapshotSource::Codex.parser_version()
                || receipt.scope != scope
                || receipt.records == 0
                || !is_sha256_hex(&receipt.prefix_digest)
                || receipt.tiers.len() > MAX_APPLIED_TIERS
                || receipt.tiers.iter().any(|(key, source)| {
                    !is_sha256_hex(key)
                        || source.is_empty()
                        || source.len() > 64
                        || !source
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._[]".contains(&byte))
                })
        }) || (required && previous.is_none());
        Self {
            previous,
            digest: ContentDigest(Sha256::new()),
            records: 0,
            matched: BTreeSet::new(),
            tiers: BTreeMap::new(),
            scope,
            prefix_matched: false,
            invalid,
        }
    }
    pub(super) fn observe(&mut self, value: &Value) {
        self.records += 1;
        if serde_json::to_writer(&mut self.digest, value).is_err() {
            self.invalid = true;
        }
        self.digest.0.update(b"\n");
        if let Some(previous) = &self.previous {
            if self.records == previous.records {
                self.prefix_matched =
                    format!("{:x}", self.digest.0.clone().finalize()) == previous.prefix_digest;
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn selector(
        &mut self,
        value: &Value,
        selector: &mut SelectorCapture,
        current: &SelectorCapture,
        model: Option<&str>,
        effort: Option<&str>,
        turn: Option<&str>,
    ) -> Option<(String, String)> {
        // Older cumulative-only rows still have an exact physical record and
        // ordinal. Retaining that digest does not infer response ownership.
        let event = codex_usage_event_identity(value).unwrap_or_else(|| {
            let mut digest = ContentDigest(Sha256::new());
            let _ = serde_json::to_writer(&mut digest, value);
            format!("physical_record:{:x}", digest.0.finalize())
        });
        let mut context = current.clone();
        context.merge(selector.clone());
        context.context.remove("service_tier");
        context.sources.remove("service_tier");
        let mut context_digest = ContentDigest(Sha256::new());
        let _ = serde_json::to_writer(
            &mut context_digest,
            &(context.context, context.sources, model, effort, turn),
        );
        let key = sha256_hex(&[
            "codex_applied_tier:v1",
            &self.records.to_string(),
            &event,
            &format!("{:x}", context_digest.0.finalize()),
        ]);
        if let Some(previous) = &self.previous {
            if self.records <= previous.records {
                if let Some(source) = previous.tiers.get(&key) {
                    // This restoration is exact-record scoped. Prefix validation
                    // at EOF is mandatory before any body may be emitted.
                    if !selector.context.contains_key("service_tier")
                        && !current.context.contains_key("service_tier")
                    {
                        selector.insert("service_tier", "priority".into(), source);
                    }
                }
            }
        }
        let tier = selector
            .context
            .get("service_tier")
            .or_else(|| current.context.get("service_tier"));
        if tier.map(String::as_str) == Some("priority") {
            let source = selector
                .sources
                .get("service_tier")
                .or_else(|| current.sources.get("service_tier"))?
                .clone();
            Some((key, source))
        } else {
            None
        }
    }
    pub(super) fn admitted(&mut self, tier: Option<(String, String)>) {
        if let Some((key, source)) = tier {
            if source.len() > 64 || self.tiers.len() >= MAX_APPLIED_TIERS {
                self.invalid = true;
                return;
            }
            self.matched.insert(key.clone());
            self.tiers.insert(key, source);
        }
    }
    pub(super) fn finish(self) -> Result<Option<AppliedTierReceipt>> {
        anyhow::ensure!(
            !self.invalid,
            "Codex applied-tier receipt is unavailable or exceeds its bound"
        );
        if let Some(previous) = &self.previous {
            anyhow::ensure!(
                self.prefix_matched && previous.tiers.keys().all(|key| self.matched.contains(key)),
                "Codex protected pricing prefix or contribution context changed"
            );
        }
        if self.tiers.is_empty() {
            return Ok(None);
        }
        Ok(Some(AppliedTierReceipt {
            version: RECEIPT_VERSION,
            derivation: SnapshotSource::Codex.parser_version().into(),
            scope: self.scope,
            records: self.records,
            prefix_digest: format!("{:x}", self.digest.0.finalize()),
            tiers: self.tiers,
        }))
    }
}
crate::heap_layout_bound::fields!(AppliedTierReceipt; version, derivation, scope, records, prefix_digest, tiers);
crate::heap_layout_bound::fields!(TierReplay; previous, digest, records, matched, tiers, scope, prefix_matched, invalid);
/// A proof pass followed by the existing parser, with a physical-line yield in
/// both passes. Only the canonical copies contribute to the derived body.
type ReplayedGroup = (
    OwnedJsonlParser,
    CandidateFile,
    Vec<CandidateFile>,
    BTreeMap<String, Option<AppliedTierReceipt>>,
);
pub(super) struct GroupReader {
    pub(super) members: Vec<CandidateFile>,
    proofs: Vec<MemberProof>,
    identified: usize,
    proof_reader: Option<OwnedJsonlParser>,
    proof: ProofBuilder,
    records: usize,
    replay_order: VecDeque<usize>,
    canonical_order: Vec<usize>,
    proof_prefix_matched: bool,
    replay_member: Option<usize>,
    parser: Option<OwnedJsonlParser>,
    replay_digest: ContentDigest,
    report: JsonlReadReport,
    pub(super) applied_receipts: BTreeMap<String, Option<AppliedTierReceipt>>,
    previous_receipts: BTreeMap<String, (Option<AppliedTierReceipt>, bool)>,
    receipt_scope: String,
    legacy_expected: BTreeMap<String, String>,
    legacy_baselines: Vec<LegacyBaseline>,
}
impl GroupReader {
    pub(super) fn new(members: Vec<CandidateFile>) -> Result<Self> {
        anyhow::ensure!(
            members.len() >= 2 && members.len() <= MAX_MEMBERS,
            "Codex joining member cap"
        );
        let bytes = members
            .iter()
            .try_fold(0u64, |sum, member| sum.checked_add(member.size_bytes));
        anyhow::ensure!(
            bytes.is_some_and(|bytes| bytes <= MAX_GROUP_BYTES),
            "Codex joining byte cap"
        );
        Ok(Self {
            members,
            proofs: Vec::new(),
            identified: 0,
            proof_reader: None,
            proof: ProofBuilder::default(),
            records: 0,
            replay_order: VecDeque::new(),
            canonical_order: Vec::new(),
            proof_prefix_matched: false,
            replay_member: None,
            parser: None,
            replay_digest: ContentDigest(Sha256::new()),
            report: JsonlReadReport::default(),
            applied_receipts: BTreeMap::new(),
            previous_receipts: BTreeMap::new(),
            receipt_scope: String::new(),
            legacy_expected: BTreeMap::new(),
            legacy_baselines: Vec::new(),
        })
    }
    pub(super) fn configure_receipts(&mut self, index: &ScanIndex) {
        self.receipt_scope = index
            .active_upload_context_fingerprint
            .clone()
            .unwrap_or_default();
        for member in &self.members {
            let key = local_index_key(&member.path);
            if let Some(entry) = index.files.get(&key) {
                if entry.codex_joined_member_set.is_none()
                    && entry.codex_applied_tier_receipt.is_none()
                    && entry.codex_captured_tier_receipt.is_none()
                {
                    if let Some(expected) = &entry.last_snapshot_fingerprint {
                        self.legacy_expected.insert(key.clone(), expected.clone());
                    }
                }
                self.previous_receipts
                    .insert(key, receipt_state(Some(entry)));
            }
        }
    }
    pub(super) fn unchanged_joined(&self, index: &ScanIndex) -> bool {
        if self.identified != self.members.len() || !self.proofs.is_empty() {
            return false;
        }
        let witness = member_set_witness(&self.members);
        self.members.iter().all(|member| {
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
    #[allow(clippy::too_many_arguments)]
    pub(super) fn step(
        &mut self,
        metadata: &CodexTitleMetadata,
        traces: Option<Arc<CodexTurnTraceMap>>,
        ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
        artifacts: bool,
        context_curve: bool,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<bool> {
        if self.identified < self.members.len() {
            let i = self.identified;
            let mut census = ScanCensus::default();
            let (opened, _file) = open_and_identify_scan_candidate(
                SnapshotSource::Codex,
                self.members[i].clone(),
                &mut census,
                None,
                0,
            )
            .context("Codex joining member could not open")?;
            self.members[i] = opened;
            self.identified += 1;
            return Ok(false);
        }
        if self.proofs.len() < self.members.len() {
            let i = self.proofs.len();
            if self.proof_reader.is_none() {
                let mut opened = self.members[i].clone();
                let file = open_candidate_file(SnapshotSource::Codex, &mut opened)?;
                anyhow::ensure!(
                    opened.opened_object_identity == self.members[i].opened_object_identity,
                    "Codex joining proof object changed before read"
                );
                let previous = self
                    .previous_receipts
                    .get(&local_index_key(&self.members[i].path));
                self.proof_prefix_matched =
                    previous.map_or(true, |(receipt, required)| !required && receipt.is_none());
                anyhow::ensure!(
                    previous.map_or(true, |(receipt, required)| (!required || receipt.is_some())
                        && receipt.as_ref().map_or(true, |receipt| receipt.version
                            == RECEIPT_VERSION
                            && receipt.derivation == SnapshotSource::Codex.parser_version()
                            && receipt.scope == self.receipt_scope
                            && receipt.tiers.len() <= MAX_APPLIED_TIERS)),
                    "Codex protected copy receipt is unavailable"
                );
                self.proof_reader = Some(OwnedJsonlParser::new(
                    file,
                    &self.members[i].path,
                    SnapshotSource::Codex,
                    apply_codex_line,
                    Some(metadata),
                    traces,
                    ledgers,
                    artifacts,
                    context_curve,
                )?);
                return Ok(false);
            }
            let reader = self.proof_reader.as_mut().expect("proof reader opened");
            let proof = &mut self.proof;
            let records = &mut self.records;
            let previous = self
                .previous_receipts
                .get(&local_index_key(&self.members[i].path))
                .and_then(|(receipt, _)| receipt.as_ref());
            let prefix_matched = &mut self.proof_prefix_matched;
            let complete = reader.step_with_observer(|value| {
                *records += 1;
                proof.observe(value);
                if let Some(previous) = previous {
                    if proof.records == previous.records {
                        *prefix_matched = format!("{:x}", proof.content.0.clone().finalize())
                            == previous.prefix_digest;
                    }
                }
            })?;
            anyhow::ensure!(
                self.records <= MAX_RECORDS,
                "Codex joining retained record cap"
            );
            if !complete {
                return Ok(false);
            }
            anyhow::ensure!(
                reader.reader.report.complete(),
                "Codex joining physical line loss"
            );
            anyhow::ensure!(
                opened_object_identity(SnapshotSource::Codex, reader.reader.reader.get_mut())?
                    == self.members[i].opened_object_identity,
                "Codex joining proof object changed"
            );
            anyhow::ensure!(
                self.proof_prefix_matched,
                "Codex protected copy prefix changed"
            );
            self.proofs.push(
                std::mem::take(&mut self.proof)
                    .finish()
                    .context("Codex joining contribution proof failed")?,
            );
            if let Some(expected) = self
                .legacy_expected
                .get(&local_index_key(&self.members[i].path))
            {
                let member = &self.members[i];
                let parsed = self
                    .proof_reader
                    .take()
                    .expect("proof parser completed")
                    .finish(
                        &member.opened_object_identity,
                        &member.path,
                        "1970-01-01T00:00:00Z",
                        member.source_file_fingerprint.clone(),
                        Some(metadata),
                        None,
                        attribution_context,
                    )?;
                anyhow::ensure!(
                    parsed.complete(),
                    "Codex legacy pricing baseline is incomplete"
                );
                let mut snapshots = parsed.snapshots;
                for snapshot in &mut snapshots {
                    apply_codex_state_evidence(snapshot, metadata);
                }
                self.legacy_baselines.push(LegacyBaseline {
                    owner: self.proofs[i].owner.clone(),
                    index_key: local_index_key(&member.path),
                    expected: expected.clone(),
                    snapshots,
                });
            }
            self.proof_reader = None;
            if self.proofs.len() == self.members.len() {
                self.canonical_order =
                    disjoint_plan(&self.proofs).context("Codex joining overlap or gap")?;
                for canonical in &mut self.canonical_order {
                    // Prefer the existing applied evidence when a newly named
                    // complete copy sorts before a previously priced member.
                    if let Some(preferred) = self
                        .proofs
                        .iter()
                        .enumerate()
                        .filter(|(_, proof)| proof.content == self.proofs[*canonical].content)
                        .filter_map(|(i, _)| {
                            self.previous_receipts
                                .get(&local_index_key(&self.members[i].path))
                                .and_then(|(receipt, _)| receipt.as_ref())
                                .map(|receipt| (receipt.records, i))
                        })
                        .max()
                    {
                        *canonical = preferred.1;
                    }
                }
                self.replay_order = self.canonical_order.clone().into();
                // The response/event sets have served their purpose. Replay keeps
                // only the full-content hash for each frozen member.
                for proof in &mut self.proofs {
                    proof.responses.clear();
                    proof.ui_events.clear();
                }
            }
            return Ok(false);
        }
        if self.replay_member.is_none() {
            let Some(i) = self.replay_order.pop_front() else {
                return Ok(true);
            };
            let member = &self.members[i];
            let mut opened = member.clone();
            let file = open_candidate_file(SnapshotSource::Codex, &mut opened)?;
            anyhow::ensure!(
                opened.opened_object_identity == member.opened_object_identity,
                "Codex joining replay object changed"
            );
            if let Some(parser) = self.parser.as_mut() {
                parser.reader =
                    BoundedJsonlReader::new(BufReader::new(file), MAX_JSONL_LINE_BYTES, true);
                // Context that was inferred in one physical file must not price
                // an unrelated record at the beginning of another file.
                parser.accumulator.current_selector = SelectorCapture::default();
                parser.accumulator.latest_model = None;
                parser.accumulator.latest_reasoning_effort = None;
                parser.accumulator.latest_turn_id = None;
            } else {
                self.parser = Some(OwnedJsonlParser::new(
                    file,
                    &member.path,
                    SnapshotSource::Codex,
                    apply_codex_line,
                    Some(metadata),
                    traces,
                    ledgers,
                    artifacts,
                    context_curve,
                )?);
            }
            let previous = self
                .previous_receipts
                .get(&local_index_key(&member.path))
                .cloned()
                .unwrap_or_default();
            self.parser
                .as_mut()
                .expect("replay parser opened")
                .accumulator
                .codex_tier_replay = Some(TierReplay::new(
                previous.0,
                previous.1,
                self.receipt_scope.clone(),
            ));
            self.replay_digest = ContentDigest(Sha256::new());
            self.replay_member = Some(i);
            return Ok(false);
        }
        let i = self.replay_member.expect("replay member opened");
        let parser = self.parser.as_mut().expect("replay parser opened");
        let digest = &mut self.replay_digest;
        if !parser.step_with_observer(|value| {
            // Serialization is identical to the proof pass and cannot retain
            // content. An error propagates through the digest's result below.
            let _ = serde_json::to_writer(&mut *digest, value);
            digest.0.update(b"\n");
        })? {
            return Ok(false);
        }
        anyhow::ensure!(
            parser.reader.report.complete(),
            "Codex joining replay line loss"
        );
        anyhow::ensure!(
            opened_object_identity(SnapshotSource::Codex, parser.reader.reader.get_mut())?
                == self.members[i].opened_object_identity,
            "Codex joining replay object changed"
        );
        let observed = format!(
            "{:x}",
            std::mem::replace(&mut self.replay_digest, ContentDigest(Sha256::new()))
                .0
                .finalize()
        );
        anyhow::ensure!(
            observed == self.proofs[i].content,
            "Codex joining replay content changed"
        );
        let receipt = parser
            .accumulator
            .codex_tier_replay
            .take()
            .expect("member receipt capture installed")
            .finish()?;
        self.applied_receipts
            .insert(local_index_key(&self.members[i].path), receipt);
        let report = parser.reader.report;
        self.report.physical_line_count += report.physical_line_count;
        self.report.parsed_json_line_count += report.parsed_json_line_count;
        self.replay_member = None;
        if self.replay_order.is_empty() {
            parser.reader.report = self.report;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn take_legacy_baselines(&mut self) -> Vec<LegacyBaseline> {
        std::mem::take(&mut self.legacy_baselines)
    }
    pub(super) fn finish(mut self) -> Result<ReplayedGroup> {
        anyhow::ensure!(
            self.replay_member.is_none() && self.replay_order.is_empty(),
            "Codex joining replay unfinished"
        );
        let parser = self.parser.take().context("Codex joining lacks a parser")?;
        // The final reader descriptor owns the final canonical member, selected
        // by the same counter order used above (not physical path order).
        let order = &self.canonical_order;
        for i in 0..self.members.len() {
            let key = local_index_key(&self.members[i].path);
            if self.applied_receipts.contains_key(&key) {
                continue;
            }
            let canonical = *order
                .iter()
                .find(|canonical| self.proofs[**canonical].content == self.proofs[i].content)
                .context("Codex copy has no canonical member")?;
            let receipt = self
                .applied_receipts
                .get(&local_index_key(&self.members[canonical].path))
                .cloned()
                .context("Codex copy lacks applied receipt")?;
            if let Some(previous) = self
                .previous_receipts
                .get(&key)
                .and_then(|(receipt, _)| receipt.as_ref())
            {
                anyhow::ensure!(
                    receipt.as_ref().is_some_and(|current| previous
                        .tiers
                        .iter()
                        .all(|(key, source)| current.tiers.get(key) == Some(source))),
                    "Codex complete copies have conflicting applied pricing"
                );
            }
            self.applied_receipts.insert(key, receipt);
        }
        let last = self.members[*order.last().context("Codex joining empty plan")?].clone();
        Ok((parser, last, self.members, self.applied_receipts))
    }
}
crate::heap_layout_bound::fields!(GroupReader; members, proofs, identified, proof_reader, proof, records, replay_order, canonical_order, proof_prefix_matched, replay_member, parser, replay_digest, report, applied_receipts, previous_receipts, receipt_scope, legacy_expected, legacy_baselines);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Tokens([u64; 6]);
impl Tokens {
    fn read(value: &Value) -> Option<Self> {
        Some(Self([
            value.get("input_tokens")?.as_u64()?,
            value.get("cached_input_tokens")?.as_u64()?,
            value
                .get("cache_write_input_tokens")
                .map_or(Some(0), Value::as_u64)?,
            value.get("output_tokens")?.as_u64()?,
            value.get("reasoning_output_tokens")?.as_u64()?,
            value.get("total_tokens")?.as_u64()?,
        ]))
    }
    fn before(self, delta: Self) -> Option<Self> {
        let mut values = [0; 6];
        for (i, value) in values.iter_mut().enumerate() {
            *value = self.0[i].checked_sub(delta.0[i])?;
        }
        Some(Self(values))
    }
}

struct ContentDigest(Sha256);
impl Default for ContentDigest {
    fn default() -> Self {
        Self(Sha256::new())
    }
}
impl std::io::Write for ContentDigest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// No prompt/output or raw response identity is retained. Full-record hashing
/// distinguishes complete copies from overlap without caching transcript bytes.
#[derive(Default)]
pub(super) struct ProofBuilder {
    content: ContentDigest,
    owner: Option<String>,
    first_before: Option<Tokens>,
    last_after: Option<Tokens>,
    responses: BTreeSet<String>,
    ui_events: BTreeSet<String>,
    native_usage: BTreeMap<Tokens, usize>,
    ui_usage: BTreeMap<Tokens, usize>,
    previous_ui: Option<String>,
    records: usize,
    invalid: bool,
}
impl ProofBuilder {
    pub(super) fn observe(&mut self, value: &Value) {
        self.records = self.records.saturating_add(1);
        if self.records > MAX_RECORDS {
            self.invalid = true;
            return;
        }
        if serde_json::to_writer(&mut self.content, value).is_err() {
            self.invalid = true;
        }
        self.content.0.update(b"\n");
        // Ordinal/recovery/fork histories have their own ownership rules. The
        // first disjoint-continuation domain does not splice those epochs.
        if value.get("ordinal").is_some() {
            self.invalid = true;
        }
        if let Some(meta) = codex_session_meta_payload(value) {
            let owner = resolve_codex_identity_option(codex_identity_at(meta, &["id"]));
            if self.records != 1 || owner.is_none() {
                self.invalid = true;
            }
            self.owner = owner;
        }
        if string_eq_at(value, &["type"], "token_usage_record")
            && self.observe_response(value).is_none()
        {
            self.invalid = true;
        }
        if let Some(last) = codex_last_usage(value) {
            // A context-only estimate has no priced usage; match the existing
            // reader's adjacent exact-event duplicate handling.
            if last.input_tokens == 0 && last.output_tokens == 0 {
                return;
            }
            let Some(identity) = codex_usage_event_identity(value) else {
                self.invalid = true;
                return;
            };
            if self.previous_ui.as_ref() == Some(&identity) {
                return;
            }
            self.previous_ui = Some(identity.clone());
            if !self.ui_events.insert(identity) {
                self.invalid = true;
            }
            let root = value
                .pointer("/payload/info/last_token_usage")
                .or_else(|| value.pointer("/token_count/info/last_token_usage"))
                .or_else(|| value.pointer("/info/last_token_usage"));
            match root.and_then(Tokens::read) {
                Some(tokens) => *self.ui_usage.entry(tokens).or_default() += 1,
                None => self.invalid = true,
            }
        } else if codex_total_usage(value).is_some() {
            // A cumulative-only delta cannot safely gain another member's
            // baseline. Preserve legacy single-file behavior outside this domain.
            self.invalid = true;
        }
    }
    fn observe_response(&mut self, value: &Value) -> Option<()> {
        let payload = value.get("payload")?;
        let owner = resolve_codex_identity(payload.get("thread_id")?.as_str()?);
        if self.owner.as_deref() != Some(&owner) {
            return None;
        }
        let response = payload.get("response_id")?.as_str()?;
        if response.is_empty() || response.len() > 256 {
            return None;
        }
        let identity = sha256_hex(&["codex_join_response:v1", response]);
        if !self.responses.insert(identity) {
            return None;
        }
        let usage = Tokens::read(payload.get("usage")?)?;
        let after = Tokens::read(payload.get("thread_token_usage")?)?;
        let before = after.before(usage)?;
        if self.last_after.is_some_and(|previous| previous != before) {
            return None;
        }
        self.first_before.get_or_insert(before);
        self.last_after = Some(after);
        *self.native_usage.entry(usage).or_default() += 1;
        Some(())
    }
    pub(super) fn finish(self) -> Option<MemberProof> {
        if self.invalid
            || self.responses.is_empty()
            || self
                .ui_usage
                .iter()
                .any(|(usage, count)| self.native_usage.get(usage).copied().unwrap_or(0) < *count)
        {
            return None;
        }
        Some(MemberProof {
            content: format!("{:x}", self.content.0.finalize()),
            owner: self.owner?,
            before: self.first_before?,
            after: self.last_after?,
            responses: self.responses,
            ui_events: self.ui_events,
        })
    }
}

pub(super) struct MemberProof {
    pub(super) content: String,
    owner: String,
    before: Tokens,
    after: Tokens,
    responses: BTreeSet<String>,
    ui_events: BTreeSet<String>,
}
/// Returns canonical members in source-counter order. Complete copies alias a
/// canonical member; partial overlaps, gaps and resets have no admitted plan.
pub(super) fn disjoint_plan(proofs: &[MemberProof]) -> Option<Vec<usize>> {
    if proofs.len() < 2 || proofs.len() > MAX_MEMBERS {
        return None;
    }
    let owner = &proofs.first()?.owner;
    let mut copies = BTreeSet::new();
    let mut order = Vec::new();
    for (i, proof) in proofs.iter().enumerate() {
        if &proof.owner != owner {
            return None;
        }
        if copies.insert(proof.content.as_str()) {
            order.push(i);
        }
    }
    order.sort_by_key(|i| proofs[*i].before);
    let mut previous = Tokens::default();
    let mut responses = BTreeSet::new();
    let mut ui_events = BTreeSet::new();
    for i in &order {
        let proof = &proofs[*i];
        if proof.before != previous {
            return None;
        }
        for response in &proof.responses {
            if !responses.insert(response) {
                return None;
            }
        }
        for event in &proof.ui_events {
            if !ui_events.insert(event) {
                return None;
            }
        }
        previous = proof.after;
    }
    Some(order)
}

impl crate::heap_layout_bound::HeapLayoutBound for ContentDigest {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Tokens {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
crate::heap_layout_bound::fields!(ProofBuilder; content, owner, first_before, last_after, responses, ui_events, native_usage, ui_usage, previous_ui, records, invalid);
crate::heap_layout_bound::fields!(MemberProof; content, owner, before, after, responses, ui_events);

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn usage(input: u64) -> Value {
        json!({"input_tokens":input,"cached_input_tokens":0,"cache_write_input_tokens":0,
            "output_tokens":0,"reasoning_output_tokens":0,"total_tokens":input})
    }
    fn member(owner: &str, response: &str, input: u64, cumulative: u64) -> Vec<Value> {
        vec![
            json!({"type":"session_meta","timestamp":"2026-10-01T10:00:00Z","payload":{"id":owner}}),
            json!({"type":"token_usage_record","timestamp":"2026-10-01T10:01:00Z","payload":{
                "thread_id":owner,"response_id":response,"usage":usage(input),"thread_token_usage":usage(cumulative)}}),
            json!({"type":"event_msg","timestamp":format!("2026-10-01T10:{:02}:01Z",cumulative / 100),
                "payload":{"type":"token_count","info":{"last_token_usage":usage(input),"total_token_usage":usage(cumulative)}}}),
        ]
    }
    fn proof(rows: &[Value]) -> MemberProof {
        let mut builder = ProofBuilder::default();
        for row in rows {
            builder.observe(row);
        }
        builder
            .finish()
            .expect("synthetic member has complete native contribution proof")
    }
    fn fixture() -> (PathBuf, HeaderInventory) {
        let root = std::env::temp_dir().join(format!(
            "ottto-codex-join-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sessions = root.join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let mut paths = BTreeSet::new();
        for (name, rows) in [
            ("a", member(owner, "r-a", 100, 100)),
            ("b", member(owner, "r-b", 200, 300)),
        ] {
            let path = sessions.join(format!("{name}.jsonl"));
            let body = rows
                .iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>();
            fs::write(&path, body).unwrap();
            paths.insert(local_index_key(&path));
        }
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        (root, inventory)
    }
    #[test]
    fn header_inventory_detects_late_members_and_owner_changes() {
        let (root, inventory) = fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        inventory.validate_membership(owner, &root).unwrap();
        fs::write(root.join("sessions/new.jsonl"), "new member").unwrap();
        assert!(inventory.validate_membership(owner, &root).is_err());
        fs::remove_dir_all(root).unwrap();
        let (root, inventory) = fixture();
        let rows = member("ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        assert!(inventory.validate_membership(owner, &root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn group_replay_uses_native_parser_and_revalidates_both_passes() {
        let (root, inventory) = fixture();
        let members = inventory.groups().into_values().next().unwrap().members;
        let mut group = GroupReader::new(members).unwrap();
        while !group
            .step(
                &CodexTitleMetadata::default(),
                None,
                None,
                false,
                false,
                None,
            )
            .unwrap()
        {}
        let (parser, last, members, _receipts) = group.finish().unwrap();
        assert_eq!(members.len(), 2);
        let parsed = parser
            .finish(
                &last.opened_object_identity,
                &last.path,
                "2026-10-01T12:00:00Z",
                last.source_file_fingerprint,
                Some(&CodexTitleMetadata::default()),
                None,
                None,
            )
            .unwrap();
        assert!(parsed.complete());
        assert_eq!(parsed.snapshots.len(), 1);
        assert_eq!(parsed.snapshots[0].input_tokens, 300);
        assert_eq!(parsed.report.parsed_json_line_count, 6);
        fs::remove_dir_all(root).unwrap();
    }
    pub(crate) fn native_join_fixture_root(priority: bool) -> PathBuf {
        let root = fixture().0;
        if priority {
            let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
            let mut rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
            rows.insert(
                1,
                json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
            );
            fs::write(
                root.join("sessions/b.jsonl"),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            let connection = Connection::open(root.join("logs_2.sqlite")).unwrap();
            connection.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, ts INTEGER, feedback_log_body TEXT)", []).unwrap();
            connection.execute("INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)", rusqlite::params![
                unix_seconds(SystemTime::now()).unwrap() as i64,
                format!("turn{{turn.id={turn}}}: websocket request: {{\"type\":\"response.create\",\"service_tier\":\"priority\",\"model\":\"gpt-5.2\"}}")
            ]).unwrap();
        }
        root
    }
    fn scan(root: &Path, index: ScanIndex, limit: usize) -> (ScanIndex, SourceScanResult) {
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            index,
            "2026-10-06T23:00:00Z",
            7,
            limit,
            false,
            None,
            &[],
            false,
            false,
        );
        for _ in 0..1000 {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan } => return (index, scan),
            }
        }
        panic!("bounded native scan did not finish");
    }
    #[test]
    fn production_scanner_aliases_need_common_settlement_and_skip_on_restart() {
        let (root, _) = fixture();
        let previous = ScanIndex::default();
        let (mut index, mut result) = scan(&root, previous.clone(), 2);
        assert_eq!(result.scanned_file_count, 2);
        assert_eq!(result.snapshots.len(), 2, "one alias per physical member");
        assert!(result.snapshots.iter().all(|item| item.input_tokens == 300));
        assert!(result.census_complete, "{result:?}");
        result
            .codex_joining_validator()
            .unwrap()
            .validate(&result.snapshots)
            .unwrap();
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            accepted.len(),
            1,
            "physical aliases share one body identity"
        );
        assert_eq!(
            index
                .committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new())
                .files
                .len(),
            0,
            "lost ACK cannot settle either new physical member"
        );
        let mut settled = index.committable_subset(&previous, &accepted, &BTreeMap::new());
        assert_eq!(settled.files.len(), 2);
        let path = root.join("index.json");
        settled.save(&path).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        let (_index, restarted) = scan(&root, loaded, 2);
        assert!(
            restarted.snapshots.is_empty(),
            "an acknowledged group needs no new upload"
        );
        assert_eq!(restarted.semantic_noop_count, 2);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn applied_priority_survives_trace_expiry_without_pricing_appended_same_turn() {
        let (root, inventory) = fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let mut rows = member(owner, "r-b", 200, 300);
        rows.insert(
            1,
            json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
        );
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut group =
            GroupReader::new(inventory.groups().into_values().next().unwrap().members).unwrap();
        let mut traces = CodexTurnTraceMap::default();
        traces.priority_turns.insert(turn.into());
        while !group
            .step(
                &CodexTitleMetadata::default(),
                Some(Arc::new(traces.clone())),
                None,
                false,
                false,
                None,
            )
            .unwrap()
        {}
        let (_parser, _last, members, receipts) = group.finish().unwrap();
        let mut index = ScanIndex::default();
        for member in members {
            let key = local_index_key(&member.path);
            index.record(member, None, ScanParseOutcome::Snapshot);
            let entry = index.files.get_mut(&key).unwrap();
            entry.codex_applied_tier_receipt = receipts[&key].clone();
            entry.codex_applied_tier_receipt_required = entry.codex_applied_tier_receipt.is_some();
        }
        let appended = member(owner, "r-c", 200, 500);
        rows.extend(appended.into_iter().skip(1));
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (_, fresh) = {
            // Reuse the real roots and make a fresh header census after append.
            let paths = inventory
                .headers
                .iter()
                .map(|header| local_index_key(&header.candidate.path))
                .collect();
            let mut directories = DirectoryCensus::new();
            let sessions = root.join("sessions");
            directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
            let mut fresh = HeaderInventory::new(&[sessions], &paths, Some(&directories));
            while !fresh.step(&CodexTitleMetadata::default()) {}
            ((), fresh)
        };
        let mut group =
            GroupReader::new(fresh.groups().into_values().next().unwrap().members).unwrap();
        group.configure_receipts(&index);
        while !group
            .step(
                &CodexTitleMetadata::default(),
                None,
                None,
                false,
                false,
                None,
            )
            .unwrap()
        {}
        let (parser, last, _members, receipts) = group.finish().unwrap();
        let parsed = parser
            .finish(
                &last.opened_object_identity,
                &last.path,
                "2026-10-06T23:00:00Z",
                last.source_file_fingerprint,
                Some(&CodexTitleMetadata::default()),
                None,
                None,
            )
            .unwrap();
        assert!(parsed.complete());
        let item = &parsed.snapshots[0];
        assert_eq!(item.input_tokens, 500);
        let priority = item
            .model_usage
            .iter()
            .filter(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
            })
            .map(|row| row.input_tokens)
            .sum::<u64>();
        assert_eq!(
            priority, 200,
            "only the previously applied physical contribution stays priority"
        );
        assert_eq!(
            receipts[&local_index_key(&root.join("sessions/b.jsonl"))]
                .as_ref()
                .unwrap()
                .tiers
                .len(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn singleton_headers_across_distinct_homes_cannot_overwrite_one_owner() {
        let (root, _) = fixture();
        let other = root.join("other-home/sessions");
        fs::create_dir_all(&other).unwrap();
        fs::rename(root.join("sessions/b.jsonl"), other.join("b.jsonl")).unwrap();
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions"), other],
            ScanIndex::default(),
            "2026-10-06T23:00:00Z",
            7,
            2,
            false,
            None,
            &[],
            false,
            false,
        );
        loop {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan } => {
                    assert!(scan.snapshots.is_empty());
                    assert_eq!(scan.ownership_incomplete_file_count, 2);
                    assert!(index.files.is_empty());
                    break;
                }
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn incomplete_native_replay_cannot_publish_a_partial_joined_replacement() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        let bad = json!({"type":"event_msg","payload":{"type":"token_count","info":{
            "total_token_usage":{"input_tokens":"not-a-number","output_tokens":"not-a-number"}}}});
        assert!(codex_total_usage(&bad).is_none());
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str(&(serde_json::to_string(&bad).unwrap() + "\n"));
        fs::write(&path, text).unwrap();
        let (after, held) = scan(&root, previous.clone(), 2);
        assert!(held.snapshots.is_empty());
        assert!(!held.census_complete);
        assert_eq!(held.ownership_incomplete_file_count, 2);
        assert_eq!(
            serde_json::to_value(&after.files).unwrap(),
            serde_json::to_value(&previous.files).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn losing_a_joined_member_cannot_replace_history_with_the_remaining_tail() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 200, 500)
            .into_iter()
            .skip(1)
        {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
        fs::write(path, text).unwrap();
        let (after, held) = scan(&root, previous.clone(), 2);
        assert!(held.snapshots.is_empty());
        assert!(!held.census_complete);
        assert_eq!(held.ownership_incomplete_file_count, 1);
        assert_eq!(
            serde_json::to_value(&after.files).unwrap(),
            serde_json::to_value(&previous.files).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_protected_receipt_rewrite_scope_change_or_cap_holds_correction() {
        let rows = member("owner", "r", 100, 100);
        let mut replay = TierReplay::new(None, false, "scope".into());
        for row in &rows {
            replay.observe(row);
        }
        replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
        let receipt = replay.finish().unwrap().unwrap();
        assert!(TierReplay::new(None, true, "scope".into())
            .finish()
            .is_err());
        let mut changed = rows.clone();
        changed[0]["payload"]["id"] = json!("other");
        for (rows, scope) in [
            (changed.as_slice(), "scope"),
            (rows.as_slice(), "other-scope"),
        ] {
            let mut replay = TierReplay::new(Some(receipt.clone()), true, scope.into());
            for row in rows {
                replay.observe(row);
            }
            replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
            assert!(replay.finish().is_err());
        }
        let mut replay = TierReplay::new(None, false, "scope".into());
        for i in 0..=MAX_APPLIED_TIERS {
            replay.admitted(Some((format!("{i:064x}"), "derived_from_logs_2".into())));
        }
        assert!(replay.finish().is_err());
    }
    #[test]
    fn malformed_or_missing_captured_metadata_holds_without_resetting_index() {
        for malformed in [Value::Null, json!({"version":"future","opaque":true})] {
            let root = native_join_fixture_root(true);
            let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
            finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
            let (mut captured, changed, held) =
                working.stage_codex_tier_capture(&ScanIndex::default(), &result.snapshots);
            assert_eq!(changed.len(), 1);
            assert!(held.is_empty());
            let path = root.join("capture.json");
            captured.save(&path).unwrap();
            let key = captured.files.keys().next().unwrap().clone();
            let mut value = serde_json::to_value(&captured).unwrap();
            value["files"][&key]["codex_captured_tier_receipt"] = malformed;
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(
                loaded.files.len(),
                1,
                "receipt damage must not reset protected state"
            );
            fs::remove_file(root.join("logs_2.sqlite")).unwrap();
            let (after, held) = scan(&root, loaded, 2);
            assert!(held.snapshots.is_empty());
            assert_eq!(held.ownership_incomplete_file_count, 2);
            assert!(after.files[&key].codex_captured_uncommitted);
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn capture_cap_refuses_group_without_evicting_known_selectors() {
        let root = native_join_fixture_root(true);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let entry = working
            .files
            .values()
            .find(|entry| entry.codex_applied_tier_receipt.is_some())
            .unwrap();
        let mut full = entry.clone();
        full.codex_applied_tier_receipt.as_mut().unwrap().tiers = (0..MAX_APPLIED_TIERS)
            .map(|n| {
                (
                    sha256_hex(&["synthetic-tier", &n.to_string()]),
                    "derived_from_logs_2".into(),
                )
            })
            .collect();
        let mut previous = ScanIndex::default();
        let bytes = full
            .codex_applied_tier_receipt
            .as_ref()
            .unwrap()
            .retained_bytes();
        for n in 0..=(MAX_RECEIPT_BYTES / bytes) {
            previous
                .files
                .insert(format!("synthetic-existing-{n}"), full.clone());
        }
        let before = serde_json::to_vec(&previous).unwrap();
        let (captured, changed, held) =
            working.stage_codex_tier_capture(&previous, &result.snapshots);
        assert!(changed.is_empty());
        assert_eq!(held.len(), 1);
        assert_eq!(serde_json::to_vec(&captured).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn native_group_reports_finite_scan_capture_and_restart_cost() {
        let root = native_join_fixture_root(true);
        let start = std::time::Instant::now();
        let ((mut index, mut result), stats) =
            crate::retry_allocation_probe::measure(|| scan(&root, ScanIndex::default(), 2));
        let scan_micros = start.elapsed().as_micros();
        let header_bytes = result
            .codex_join_validation
            .as_ref()
            .unwrap()
            .inventory
            .read_bytes;
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        let (capture, _, _) =
            index.stage_codex_tier_capture(&ScanIndex::default(), &result.snapshots);
        result.finish_codex_capture_boundary(&mut index);
        let capture_bytes = serde_json::to_vec(&capture).unwrap().len();
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let settled = index.committable_subset(&capture, &accepted, &BTreeMap::new());
        let index_bytes = serde_json::to_vec(&settled).unwrap().len();
        let path = root.join("measured-index.json");
        let mut settled = settled;
        settled.save(&path).unwrap();
        fs::remove_file(root.join("logs_2.sqlite")).unwrap();
        let start = std::time::Instant::now();
        let (_, restart) = scan(&root, ScanIndex::load(&path).unwrap(), 2);
        assert!(restart.snapshots.is_empty());
        assert_eq!(restart.semantic_noop_count, 2);
        eprintln!(
            "CODEX_UNION_MEASUREMENT {}",
            json!({"synthetic_members":2,
            "selected_parser_passes":2,"header_read_bytes":header_bytes,
            "scan_microseconds":scan_micros,"scan_requested_allocation_peak":stats.requested_peak,
            "scan_usable_allocation_peak":stats.usable_peak,"capture_index_bytes":capture_bytes,
            "settled_index_bytes":index_bytes,"restart_microseconds":start.elapsed().as_micros(),
            "restart_semantic_noops":restart.semantic_noop_count,"restart_full_replays":0})
        );
        fs::remove_dir_all(root).unwrap();
    }
    fn legacy_index(
        inventory: &HeaderInventory,
        traces: Option<Arc<CodexTurnTraceMap>>,
    ) -> ScanIndex {
        let mut index = ScanIndex::default();
        for member in inventory
            .groups()
            .into_values()
            .flat_map(|group| group.members)
        {
            let mut census = ScanCensus::default();
            let (member, file) = open_and_identify_scan_candidate(
                SnapshotSource::Codex,
                member,
                &mut census,
                None,
                0,
            )
            .unwrap();
            let parsed = parse_opened_jsonl_file(
                file,
                &member.opened_object_identity,
                &member.path,
                "2026-10-06T23:00:00Z",
                member.source_file_fingerprint.clone(),
                SnapshotSource::Codex,
                apply_codex_line,
                Some(&CodexTitleMetadata::default()),
                None,
                traces.clone(),
                None,
                false,
                None,
                false,
            )
            .unwrap();
            assert!(parsed.complete());
            let fingerprints = parsed
                .snapshots
                .iter()
                .map(|item| snapshot_fingerprint(SnapshotSource::Codex, item))
                .collect::<BTreeSet<_>>();
            let mut digest = Sha256::new();
            update_length_prefixed(&mut digest, b"snapshot_file_entity_set:v1");
            for fingerprint in &fingerprints {
                update_length_prefixed(&mut digest, fingerprint.as_bytes());
            }
            let key = local_index_key(&member.path);
            index.record(
                member,
                Some(format!("{:x}", digest.finalize())),
                ScanParseOutcome::Snapshot,
            );
            index.file_snapshot_fingerprints.insert(key, fingerprints);
        }
        index
    }
    #[test]
    fn legacy_first_import_requires_actual_old_output_match_and_allows_healthy_sibling() {
        let (root, inventory) = fixture();
        let previous = legacy_index(&inventory, None);
        let (mut index, mut result) = scan(&root, previous.clone(), 2);
        assert_eq!(result.codex_legacy_join_baselines.len(), 2);
        result.reconcile_codex_legacy_joining(&mut index, &previous, "machine", |_, _| {});
        assert!(result.census_complete);
        assert_eq!(result.snapshots.len(), 2);
        fs::remove_dir_all(root).unwrap();
        let (root, inventory) = fixture();
        let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let mut rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
        rows.insert(
            1,
            json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
        );
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut traces = CodexTurnTraceMap::default();
        traces.priority_turns.insert(turn.into());
        let previous = legacy_index(&inventory, Some(Arc::new(traces)));
        let sibling = member(
            "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "r-sibling",
            100,
            100,
        );
        fs::write(
            root.join("sessions/sibling.jsonl"),
            sibling
                .iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (mut index, mut result) = scan(&root, previous.clone(), 3);
        result.reconcile_codex_legacy_joining(&mut index, &previous, "machine", |_, _| {});
        assert!(!result.census_complete);
        assert_eq!(
            result.snapshots.len(),
            1,
            "only the mismatched legacy group is held"
        );
        assert_eq!(
            result.snapshots[0].source_session_id,
            "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        );
        for (key, entry) in &previous.files {
            assert_eq!(
                index.files[key].last_snapshot_fingerprint,
                entry.last_snapshot_fingerprint
            );
        }
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .unhealthy_retry_not_before_unix_seconds
            .is_some());
        let (_index, quiet) = scan(&root, index, 3);
        assert!(quiet.snapshots.is_empty());
        assert_eq!(
            quiet.scanned_file_count, 0,
            "held unchanged group uses existing retry backoff"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn disjoint_continuation_uses_counter_order_and_collapses_complete_copies() {
        let a = member("owner", "response-a", 100, 100);
        let b = member("owner", "response-b", 200, 300);
        assert_eq!(disjoint_plan(&[proof(&b), proof(&a)]), Some(vec![1, 0]));
        assert_eq!(disjoint_plan(&[proof(&a), proof(&a)]), Some(vec![0]));
        assert_eq!(
            disjoint_plan(&[proof(&a), proof(&b), proof(&a)]),
            Some(vec![0, 1])
        );
    }
    #[test]
    fn overlapping_identity_gap_reset_or_different_owner_has_no_plan() {
        let a = member("owner", "response-a", 100, 100);
        for b in [
            member("owner", "response-a", 200, 300),
            member("owner", "response-b", 200, 400),
            member("owner", "response-b", 200, 200),
            member("other-owner", "response-b", 200, 300),
        ] {
            assert!(disjoint_plan(&[proof(&a), proof(&b)]).is_none());
        }
    }
    #[test]
    fn copied_ui_contribution_cannot_gain_a_second_member() {
        let a = member("owner", "response-a", 100, 100);
        let mut b = member("owner", "response-b", 100, 200);
        b[2] = a[2].clone();
        assert!(disjoint_plan(&[proof(&a), proof(&b)]).is_none());
    }
    #[test]
    fn missing_owner_native_fields_or_ui_coverage_is_not_accepted() {
        let rows = member("owner", "response", 100, 100);
        for field in ["thread_id", "response_id", "usage", "thread_token_usage"] {
            let mut changed = rows.clone();
            changed[1]["payload"].as_object_mut().unwrap().remove(field);
            let mut builder = ProofBuilder::default();
            for row in &changed {
                builder.observe(row);
            }
            assert!(builder.finish().is_none(), "{field}");
        }
        let mut changed = rows;
        changed[2]["payload"]["info"]["last_token_usage"] = usage(200);
        let mut builder = ProofBuilder::default();
        for row in &changed {
            builder.observe(row);
        }
        assert!(builder.finish().is_none());
    }
}
