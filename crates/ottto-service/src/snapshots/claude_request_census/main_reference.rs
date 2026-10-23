//! Frozen admission/record-wire algorithm from main4d09e46aae9ffb2ed3774139bedd5f9d606fa805.
//! Test-only independence: never calls HEAD insert, charge, admission_bytes or
//! its record serializer. Types/getters are shared; MONEY getters are unchanged.
use super::*;
// Freeze main's limits too: changing HEAD limits must not move this reference.
const MAX_CLAUDE_REQUEST_CENSUS_HASHES: usize = 2_097_152;
const MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES: usize = 48 * 1024 * 1024;
const TOMBSTONE_RESERVE_BYTES: usize = 1024 * 1024;
#[derive(Clone, Default)]
pub(crate) struct MainAdmission {
    records: BTreeMap<String, ClaudeRequestCensusRecord>,
    hash_total: usize,
    serialized_total: usize,
}
struct MainRecord<'a>(&'a ClaudeRequestCensusRecord);
impl Serialize for MainRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let record = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &record.derivation)?;
        map.serialize_entry("fp", &LowerHex(&record.source_file_fingerprint))?;
        map.serialize_entry("w", &record.window)?;
        map.serialize_entry("s", record.shape.wire())?;
        if record.twin {
            map.serialize_entry("tw", &true)?;
        }
        if record.unverified {
            map.serialize_entry("u", &true)?;
        }
        if !record.request_hashes().is_empty() {
            map.serialize_entry("b", &HashBase64(record.request_hashes()))?;
        }
        if let Some(birth) = &record.birth {
            map.serialize_entry("bi", &birth.unix_seconds)?;
            map.serialize_entry("bd", &birth.device)?;
            map.serialize_entry("bn", &birth.inode)?;
        }
        if let Some(retired) = record.retired {
            map.serialize_entry("r", &retired)?;
        }
        if let Some((requests, tokens)) = record.old_path_usage {
            map.serialize_entry("ur", &requests)?;
            map.serialize_entry("ut", &tokens)?;
        }
        if let Some(modified) = record.modified {
            map.serialize_entry("m", &modified)?;
        }
        let Some(ledger) = record.ledger.as_deref() else {
            return map.end();
        };
        if let Some(sweep) = &ledger.sweep {
            map.serialize_entry("sk", &sweep.complete_through)?;
            map.serialize_entry("sd", &sweep.debt)?;
        }
        if let Some(memo) = &ledger.family {
            map.serialize_entry("fr", &memo.removed_requests)?;
            map.serialize_entry("ft", &memo.removed_tokens)?;
            map.serialize_entry("fs", &memo.snapshot)?;
        }
        if let Some(facts) = &ledger.facts {
            map.serialize_entry("f", &BytesBase64(facts))?;
        }
        if let Some(tail) = &ledger.tail {
            map.serialize_entry("to", &tail.offset)?;
            map.serialize_entry("td", &tail.device)?;
            map.serialize_entry("tn", &tail.inode)?;
            map.serialize_entry("ta", &tail.anchor)?;
            map.serialize_entry("tc", &tail.line_sum)?;
            map.serialize_entry("tl", &tail.last_append_unix)?;
            map.serialize_entry("tv", &tail.audited_offset)?;
            map.serialize_entry("tw2", &tail.audited_unix)?;
            map.serialize_entry("tm", &tail.missing_sweeps)?;
            map.serialize_entry("te", &tail.first_event_unix)?;
            map.serialize_entry("tk", &tail.skip_bytes)?;
            if let Some(audit) = &tail.audit {
                map.serialize_entry("xa", &audit.target_offset)?;
                map.serialize_entry("xs", &audit.target_sum)?;
                map.serialize_entry("xp", &audit.position)?;
                map.serialize_entry("xq", &audit.partial_sum)?;
                map.serialize_entry("xk", &audit.skip_bytes)?;
            }
        }
        map.end()
    }
}

impl MainAdmission {
    pub(crate) fn from_census(census: &ClaudeRequestCensus) -> Self {
        let mut reference = Self::default();
        for (key, record) in &census.records {
            let record = record.clone();
            reference.charge(key, &record, true);
            reference.records.insert(key.clone(), record);
        }
        reference
    }
    pub(crate) fn into_census(self) -> ClaudeRequestCensus {
        let mut census = ClaudeRequestCensus {
            records: self.records,
            ..ClaudeRequestCensus::default()
        };
        census.recount();
        census
    }
    pub(crate) fn take(&mut self, key: &str) -> Option<ClaudeRequestCensusRecord> {
        let record = self.records.remove(key)?;
        self.charge(key, &record, false);
        Some(record)
    }
    pub(crate) fn hash_total(&self) -> usize {
        self.hash_total
    }
    pub(crate) fn get(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.records.get(key)
    }
    pub(crate) fn insert_for_test(
        &mut self,
        key: &str,
        record: impl Into<SafetyRecord>,
    ) -> ClaudeRequestCensusInsert {
        self.insert(key.to_owned(), record.into().core)
    }
    fn charge(&mut self, key: &str, record: &ClaudeRequestCensusRecord, add: bool) {
        let hashes = record.request_hashes().len();
        let bytes = entry_bytes(key, record);
        if add {
            self.hash_total += hashes;
            self.serialized_total = self.serialized_total.saturating_add(bytes);
        } else {
            self.hash_total -= hashes;
            self.serialized_total = self.serialized_total.saturating_sub(bytes);
        }
    }
    pub(crate) fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
    /// Main's MONEY maintenance at a healthy complete terminal. The D1 shadow
    /// comparison is excluded from both timing arms, since OFF does no shadow work.
    pub(crate) fn terminal(&mut self, index: &ScanIndex, observed: &BTreeSet<String>, window: u64) {
        self.records.retain(|key, _| {
            !is_ledger_key(key) && (index.files.contains_key(key) || observed.contains(key))
        });
        self.hash_total = 0;
        self.serialized_total = 0;
        for (key, record) in &self.records {
            self.hash_total += record.request_hashes().len();
            self.serialized_total += entry_bytes(key, record);
        }
        if window == 0 {
            return;
        }
        let cutoff = window.saturating_sub(CLAUDE_TRANSCRIPT_RETIREMENT_SECONDS);
        let files = &index.files;
        let census = self;
        let mut freed = (0_usize, 0_usize);
        for (key, record) in census.records.iter_mut() {
            if record.is_birth_stub()
                || record.retired.is_some()
                || record.request_hashes().is_empty()
            {
                continue;
            }
            // Not dirty: the indexed revision is still the one the record (and
            // its mtime) describes.
            let Some(entry) = files.get(key.as_str()).filter(|entry| {
                decode_fingerprint(&entry.source_file_fingerprint)
                    .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
            }) else {
                continue;
            };
            // A record written before `m` (#664) takes the entry's mtime: the
            // equal fingerprint hashes that same mtime.
            let modified = record
                .modified
                .or((entry.modified_unix_seconds > 0).then_some(entry.modified_unix_seconds));
            if !modified.is_some_and(|modified| modified < cutoff) {
                continue;
            }
            let before = (record.request_hashes().len(), entry_bytes(key, record));
            record.retire();
            let after = entry_bytes(key, record);
            freed.0 += before.0;
            freed.1 += before.1.saturating_sub(after);
        }
        census.hash_total -= freed.0;
        census.serialized_total = census.serialized_total.saturating_sub(freed.1);
    }
}
impl Serialize for MainAdmission {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.records.len()))?;
        for (key, record) in &self.records {
            map.serialize_entry(key, &MainRecord(record))?;
        }
        map.end()
    }
}
fn entry_bytes(key: &str, record: &ClaudeRequestCensusRecord) -> usize {
    // Frozen main counting writer: no allocation and no HEAD record serializer.
    fn count(value: &impl Serialize) -> usize {
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(bytes.len());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Count(0);
        serde_json::to_writer(&mut writer, value).unwrap();
        writer.0
    }
    count(&key)
        .saturating_add(count(&MainRecord(record)))
        .saturating_add(2)
}

impl MainAdmission {
    pub(crate) fn insert(
        &mut self,
        key: String,
        mut record: ClaudeRequestCensusRecord,
    ) -> ClaudeRequestCensusInsert {
        if let Some(old) = self.records.remove(&key) {
            self.charge(&key, &old, false);
        }
        let fits = |census: &Self, record: &ClaudeRequestCensusRecord, limit: usize| {
            census
                .hash_total
                .checked_add(record.request_hashes().len())
                .is_some_and(|total| total <= MAX_CLAUDE_REQUEST_CENSUS_HASHES)
                && census
                    .serialized_total
                    .checked_add(entry_bytes(&key, record))
                    .is_some_and(|total| total <= limit)
        };
        let mut outcome = ClaudeRequestCensusInsert::Stored;
        if !fits(
            self,
            &record,
            MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - TOMBSTONE_RESERVE_BYTES,
        ) {
            record.shape = ClaudeRequestCensusShape::OverBudget;
            record.request_hashes = None;
            record.retired = None;
            if let Some(fields) = record.ledger.as_mut() {
                fields.facts = None;
            }
            outcome = ClaudeRequestCensusInsert::Tombstone;
            if !fits(self, &record, MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES) {
                return ClaudeRequestCensusInsert::Refused;
            }
        }
        self.charge(&key, &record, true);
        self.records.insert(key, record);
        outcome
    }
}

/// Frozen inline layout, only for the OFF receipt (no values constructed).
#[allow(dead_code)]
pub(crate) struct MainRecordLayout {
    /// The parse's candidate fingerprint (sidecar-inclusive), whether or not
    /// the entry was recorded with it.
    source_file_fingerprint: [u8; 32],
    /// `CLAUDE_REQUEST_CENSUS_DERIVATION` at production.
    derivation: u16,
    /// The census window end (unix seconds) of the traversal that parsed it.
    window: u64,
    shape: ClaudeRequestCensusShape,
    /// The parsed content (root, member) differs from the path-derived pair.
    twin: bool,
    /// Pending ruling S2: not source-verified (a tail parse that still owes
    /// its sampled audit, or a read that cannot certify its source). D1
    /// produces it as for a verified parse and only notes it here.
    unverified: bool,
    /// Sorted, strictly ascending `claude_request_hash` of every request id
    /// (None: none). Shared, never copied, by every clone of the index (the
    /// working, committed and selected-subset copies hold one buffer).
    request_hashes: Option<Arc<[u64]>>,
    /// First-seen birth of the physical object at this key, set once and
    /// bound to its (device, inode).
    birth: Option<ClaudeRequestBirth>,
    /// Retired: the hashes were dropped (old, settled file); this is how many
    /// there were. A retired record still counts as recorded.
    retired: Option<u64>,
    /// Old-path requests and conserved tokens last built from this file.
    old_path_usage: Option<(u64, u64)>,
    /// Transcript records: the file's modification time (unix seconds) at the
    /// parse that wrote the record. Retirement reads it, never the index.
    modified: Option<u64>,
    /// P1 money ledger records only (they live in the ledger's own store,
    /// never in the scan index): boxed so transcript records stay small.
    ledger: Option<Box<ClaudeLedgerFields>>,
}

// Frozen main resident/admission formula; the layout fields above are frozen.
pub(crate) const MAIN_RECORD_RESIDENT_OVERHEAD_BYTES: usize =
    (std::mem::size_of::<String>() + std::mem::size_of::<MainRecordLayout>()) * 3 / 2
        + std::mem::size_of::<ClaudeLedgerFields>()
        + 2 * std::mem::size_of::<usize>();
