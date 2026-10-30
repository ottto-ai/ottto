//! Account mapper only; not connected to the runtime until the integration round.
//! Each map entry is a stable typed bucket, below the 64 KiB target (1 MiB cap).
//! Root counts publish the complete bucket inventory in the SAME transaction.
//! Callers discard KindCxAccounts after ANY abort/ambiguous commit; retain it
//! only with the committed graph. No position is derived from a vector index.
#![allow(dead_code)] // The integration owner replaces PendingMapper.
use super::super::{
    account_pending_retention, ClaudeAccountFamilyPending, ClaudeAccountFamilyPendingWindow,
    ClaudeAccountFamilyWitness, ClaudeAccountRequestSet, ClaudeAuthorityProofCorrection,
    ClaudeTranscriptUsageOccurrenceWitness, ClaudeUsageAuthorityQuarantineDisposition,
    ClaudeUsageAuthorityQuarantineRecord, ClaudeUsageFamilyPending, ClaudeUsageFamilyWitness,
    SessionAccountBinding,
};
use super::*;
use anyhow::{bail, ensure, Context};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const KINDS: &[&str] = &[
    "account.current",
    "account_window",
    "account.absent_members",
    "usage.pending",
    "family.requests",
    "proof.account",
    "proof.usage",
    "proof.deferred_account",
    "setting.binding",
    "refusal.authority",
    "account.window_retention",
];
const TARGET: u64 = 64 * 1024;
const RETENTION: &str = "account.window_retention";

#[derive(Default)]
pub(super) struct KindCxAccounts {
    rows: BTreeMap<(String, String), BTreeMap<RowKey, Header>>,
    ready: bool,
    /// G1 hook: alarm only, never permission to retire unsettled windows.
    pub(super) families_over_64_windows: u64,
    pub(super) buckets_over_target: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    path: Vec<String>,
    data: Data,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Data {
    Current {
        current: Option<u64>,
        next: u64,
    },
    Window {
        version: String,
        boundary: String,
        account: String,
        evidence: u128,
        complete: bool,
        invalid: bool,
        children: u64,
    },
    Usage {
        boundary: String,
        invalid: bool,
        idless: Option<[u8; 32]>,
        children: u64,
    },
    AccountProof {
        account: String,
        evidence: u128,
        children: u64,
    },
    UsageProof {
        evidence: String,
        exclusion: Option<String>,
        children: u64,
    },
    Authority {
        contract: String,
        proven: String,
        failed: u8,
        disposition: ClaudeUsageAuthorityQuarantineDisposition,
        retry: u64,
        correction: Option<String>,
        children: u64,
    },
    Binding(SessionAccountBinding),
    Number(u64),
    Text(String),
    Shared(u64),
    Occurrence(ClaudeTranscriptUsageOccurrenceWitness),
    Empty,
    Retention([u64; 6]),
}
impl Data {
    fn children(&self) -> Option<u64> {
        match self {
            Self::Window { children, .. }
            | Self::Usage { children, .. }
            | Self::AccountProof { children, .. }
            | Self::UsageProof { children, .. }
            | Self::Authority { children, .. } => Some(*children),
            _ => None,
        }
    }
}

// Zero escaped, terminated UTF-8 components preserve full strings and their
// lexicographic range order. Hashes are never used as logical identities.
fn encode(parts: &[&str]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for part in parts {
        ensure!(part.len() <= KEY_BYTES, "state_v2_string_admission");
        for b in part.bytes() {
            if b == 0 {
                out.extend_from_slice(&[0, 255]);
            } else {
                out.push(b);
            }
        }
        out.extend_from_slice(&[0, 0]);
        ensure!(out.len() <= KEY_BYTES, "state_v2_key_admission");
    }
    Ok(out)
}
fn decode(bytes: &[u8]) -> Result<Vec<String>> {
    ensure!(bytes.len() <= KEY_BYTES, "state_v2_key_admission");
    let mut parts = Vec::new();
    let mut part = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let b = bytes[at];
        at += 1;
        if b != 0 {
            part.push(b);
            continue;
        }
        let tag = *bytes.get(at).context("accounts_key")?;
        at += 1;
        match tag {
            255 => part.push(0),
            0 => {
                parts.push(String::from_utf8(std::mem::take(&mut part))?);
            }
            _ => bail!("accounts_key"),
        }
    }
    ensure!(part.is_empty() && !parts.is_empty(), "accounts_key");
    ensure!(
        encode(&parts.iter().map(String::as_str).collect::<Vec<_>>())? == bytes,
        "accounts_key"
    );
    Ok(parts)
}
fn key(kind: &str, family: &str, path: &[&str], position: u64) -> Result<RowKey> {
    let mut parts = vec![family];
    parts.extend_from_slice(path);
    RowKey::record(kind, encode(&parts)?, position)
}

struct Limited<'a> {
    out: &'a mut Vec<u8>,
    cap: u64,
}
impl Write for Limited<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if (self.out.len() as u64).saturating_add(bytes.len() as u64) > self.cap {
            return Err(std::io::Error::other("accounts_value_admission"));
        }
        self.out.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn unpack(value: &dyn Value) -> Result<Part> {
    let mut packed = Vec::new();
    value.write(&mut Limited {
        out: &mut packed,
        cap: MUTABLE_VALUE_BYTES,
    })?;
    let mut json = Vec::new();
    packed::decode(
        packed.as_slice(),
        &mut Limited {
            out: &mut json,
            cap: MUTABLE_VALUE_BYTES,
        },
    )?;
    Ok(serde_json::from_slice(&json)?)
}
fn read(tx: &mut dyn Transaction, h: &Header) -> Result<Part> {
    let mut packed = Vec::new();
    ensure!(
        h.value_version == 1 && h.len <= MUTABLE_VALUE_BYTES,
        "accounts_value_admission"
    );
    tx.read_value(
        h,
        &mut Limited {
            out: &mut packed,
            cap: MUTABLE_VALUE_BYTES,
        },
    )?;
    let mut json = Vec::new();
    packed::decode(
        packed.as_slice(),
        &mut Limited {
            out: &mut json,
            cap: MUTABLE_VALUE_BYTES,
        },
    )?;
    Ok(serde_json::from_slice(&json)?)
}
fn ref_id(part: &Part) -> Option<u64> {
    if let Data::Shared(id) = part.data {
        Some(id)
    } else {
        None
    }
}
fn release(tx: &mut dyn Transaction, h: &Header) -> Result<()> {
    if let Some(id) = ref_id(&read(tx, h)?) {
        tx.adjust_refs(&RowKey::RequestSet(id), -1)?;
    }
    Ok(())
}

struct Scope<'a> {
    tx: &'a mut dyn Transaction,
    kind: &'a str,
    family: &'a str,
    old: BTreeMap<RowKey, Header>,
    live: BTreeMap<RowKey, Header>,
    over_target: u64,
}
impl Scope<'_> {
    fn emit(&mut self, path: &[&str], position: u64, data: Data, fixed: Fixed) -> Result<()> {
        data.texts(&mut |s| {
            ensure!(s.len() <= KEY_BYTES, "state_v2_string_admission");
            Ok(())
        })?;
        let k = key(self.kind, self.family, path, position)?;
        let part = Part {
            path: path.iter().map(|p| (*p).to_owned()).collect(),
            data,
        };
        let value = packed::Json(&part);
        let row = RowInput {
            key: &k,
            fixed: &fixed,
            value_version: 1,
            value: &value,
        };
        let header = preflight(&row)?;
        self.over_target += u64::from(header.len > TARGET);
        let old = self.old.remove(&k);
        let h = match old {
            Some(h) if h.fixed == fixed && self.tx.value_matches(&h, &value)? => h,
            old => {
                if let Some(h) = old {
                    release(self.tx, &h)?;
                }
                self.tx.put(row)?
            }
        };
        ensure!(
            self.live.insert(k, h).is_none(),
            "accounts_duplicate_bucket"
        );
        Ok(())
    }
    fn plain(&mut self, path: &[&str], position: u64, data: Data) -> Result<()> {
        let fixed = match self.kind {
            // Child buckets carry no invented scan fields. Flag bit 63 marks
            // a typed bucket; the root is the ONLY semantic scan projection.
            "account_window" => Fixed::AccountPending {
                account_hash: None,
                evidence_count: 0,
                flags: 1 << 63,
                member_count: 0,
                set_count: 0,
            },
            "usage.pending" => Fixed::UsagePending {
                flags: 1 << 63,
                idless_revision: None,
                occurrence_count: 0,
                member_count: 0,
            },
            _ => Fixed::None,
        };
        self.emit(path, position, data, fixed)
    }
    fn shared(
        &mut self,
        path: &[&str],
        position: u64,
        evidence: &interning::RequestEvidence<'_>,
    ) -> Result<()> {
        let k = key(self.kind, self.family, path, position)?;
        let existing = self.old.get(&k).cloned();
        let reused = if let Some(h) = existing {
            let id = ref_id(&read(self.tx, &h)?).context("accounts_reference_shape")?;
            let shared = self
                .tx
                .get(&RowKey::RequestSet(id))?
                .context("accounts_reference_missing")?;
            if self.tx.value_matches(&shared, evidence)? {
                Some(id)
            } else {
                None
            }
        } else {
            None
        };
        let id = match reused {
            Some(id) => id,
            None => interning::intern_request_set(self.tx, evidence)?,
        };
        self.plain(path, position, Data::Shared(id))
    }
}
fn scope(
    tx: &mut dyn Transaction,
    cx: &mut KindCxAccounts,
    kind: &str,
    family: &str,
    emit: impl FnOnce(&mut Scope<'_>) -> Result<()>,
) -> Result<()> {
    cx.ready = false;
    let owner = (kind.to_owned(), family.to_owned());
    let old = cx.rows.remove(&owner).unwrap_or_default();
    let mut s = Scope {
        tx,
        kind,
        family,
        old,
        live: BTreeMap::new(),
        over_target: 0,
    };
    emit(&mut s)?;
    for h in s.old.values() {
        release(s.tx, h)?;
        s.tx.delete(&h.key)?;
    }
    cx.buckets_over_target = cx.buckets_over_target.saturating_add(s.over_target);
    if !s.live.is_empty() {
        cx.rows.insert(owner, s.live);
    }
    cx.ready = true;
    Ok(())
}
fn canonical_hash(s: &str) -> Option<[u8; 32]> {
    let b = packed::hash_string(s).ok()?;
    (b.first() == Some(&1)).then(|| b[1..].try_into().expect("HSTR width"))
}
fn account_window(s: &mut Scope<'_>, id: u64, w: &ClaudeAccountFamilyPendingWindow) -> Result<()> {
    let fixed = Fixed::AccountPending {
        account_hash: canonical_hash(&w.account_identifier_hash),
        evidence_count: w.evidence_request_count,
        flags: 1 | (u64::from(w.census_complete) << 1) | (u64::from(w.invalid) << 2),
        member_count: w.members.len() as u64,
        set_count: w.member_requests.len() as u64,
    };
    s.emit(
        &[],
        id,
        Data::Window {
            version: w.version.clone(),
            boundary: w.census_window_end.clone(),
            account: w.account_identifier_hash.clone(),
            evidence: w.evidence_request_count,
            complete: w.census_complete,
            invalid: w.invalid,
            children: (w.members.len() + w.member_requests.len()) as u64,
        },
        fixed,
    )?;
    for (m, count) in &w.members {
        s.plain(&["members", m], id, Data::Number(*count))?;
    }
    for (m, set) in &w.member_requests {
        s.shared(
            &["requests", m],
            id,
            &interning::RequestEvidence::Account {
                prefixes: &set.prefixes,
                fingerprint: &set.fingerprint,
                identity_revision: set.identity_revision.as_deref(),
                hash_count: None,
            },
        )?;
    }
    Ok(())
}
fn blank_window() -> ClaudeAccountFamilyPendingWindow {
    ClaudeAccountFamilyPendingWindow {
        version: String::new(),
        census_window_end: String::new(),
        account_identifier_hash: String::new(),
        evidence_request_count: 0,
        census_complete: false,
        members: BTreeMap::new(),
        member_requests: BTreeMap::new(),
        invalid: false,
    }
}

// IDs live in the persisted pointer even after deleting the final window.
// Recreating a family cannot reuse an old ID. Surviving windows retain IDs
// when the middle is removed; a boundary spelling is never normalized.
fn windows(
    prev: Option<&ClaudeAccountFamilyPending>,
    next: Option<&ClaudeAccountFamilyPending>,
    family: &str,
    tx: &mut dyn Transaction,
    cx: &mut KindCxAccounts,
) -> Result<()> {
    let pointer = key("account.current", family, &[], 0)?;
    let (old_current, mut high) = match tx.get(&pointer)? {
        Some(h) => match read(tx, &h)?.data {
            Data::Current { current, next } => (current, next),
            _ => bail!("accounts_pointer_shape"),
        },
        None => {
            ensure!(prev.is_none(), "accounts_pointer_missing");
            (None, 1)
        }
    };
    ensure!(
        high > 0 && high <= i64::MAX as u64 + 1,
        "accounts_ordinal_exhausted"
    );
    let mut ids = Vec::new();
    if let Some(rows) = cx.rows.get(&("account_window".into(), family.into())) {
        for k in rows.keys() {
            if let RowKey::Record {
                key_bytes,
                position,
                ..
            } = k
            {
                if decode(key_bytes)?.len() == 1 {
                    ids.push(*position);
                }
            }
        }
    }
    ids.sort_unstable();
    let old: Vec<_> = prev
        .into_iter()
        .flat_map(|p| p.previous_windows.iter().chain(std::iter::once(&p.current)))
        .collect();
    ensure!(
        old.len() == ids.len() && ids.last().copied() == old_current,
        "accounts_window_inventory"
    );
    ensure!(
        ids.iter().all(|id| *id > 0 && *id < high),
        "accounts_high_water"
    );
    let wanted: Vec<_> = next
        .into_iter()
        .flat_map(|p| p.previous_windows.iter().chain(std::iter::once(&p.current)))
        .collect();
    let mut boundaries = BTreeSet::new();
    ensure!(
        old.iter().all(|w| boundaries.insert(&w.census_window_end)),
        "accounts_ambiguous_boundary"
    );
    let mut plan = Vec::new();
    let mut after = 0;
    for w in &wanted {
        let found = old
            .iter()
            .enumerate()
            .skip(after)
            .find(|(_, old)| old.census_window_end == w.census_window_end);
        let id = if let Some((at, _)) = found {
            after = at + 1;
            ids[at]
        } else {
            ensure!(high <= i64::MAX as u64, "accounts_ordinal_exhausted");
            let id = high;
            high += 1;
            id
        };
        ensure!(
            plan.last().map_or(true, |last| *last < id),
            "accounts_window_order"
        );
        plan.push(id);
    }
    if wanted.len() > 64 {
        cx.families_over_64_windows = cx.families_over_64_windows.saturating_add(1);
    }
    scope(tx, cx, "account_window", family, |s| {
        for (w, id) in wanted.iter().zip(&plan) {
            account_window(s, *id, w)?;
        }
        Ok(())
    })?;
    scope(tx, cx, "account.current", family, |s| {
        s.plain(
            &[],
            0,
            Data::Current {
                current: plan.last().copied(),
                next: high,
            },
        )
    })?;
    scope(tx, cx, "account.absent_members", family, |s| {
        if let Some(p) = next {
            s.plain(
                &[],
                0,
                Data::Number(p.confirmed_absent_members.len() as u64),
            )?;
            for m in &p.confirmed_absent_members {
                s.plain(&[m], 0, Data::Empty)?;
            }
        }
        Ok(())
    })
}

fn usage(s: &mut Scope<'_>, p: &ClaudeUsageFamilyPending) -> Result<()> {
    let occurrences = p
        .member_occurrences
        .values()
        .map(BTreeMap::len)
        .sum::<usize>();
    s.emit(
        &[],
        0,
        Data::Usage {
            boundary: p.census_window_end.clone(),
            invalid: p.invalid,
            idless: p.idless_revision,
            children: (p.member_occurrences.len() + occurrences) as u64,
        },
        Fixed::UsagePending {
            flags: 1 | (u64::from(p.invalid) << 1),
            idless_revision: p.idless_revision,
            occurrence_count: occurrences as u64,
            member_count: p.member_occurrences.len() as u64,
        },
    )?;
    for (m, entries) in &p.member_occurrences {
        s.plain(&[m], 0, Data::Empty)?;
        for (r, o) in entries {
            s.plain(&[m, r], 0, Data::Occurrence(o.clone()))?;
        }
    }
    Ok(())
}
fn request_map(s: &mut Scope<'_>, map: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    s.plain(&[], 0, Data::Number(map.len() as u64))?;
    for (m, hashes) in map {
        s.shared(
            &[m],
            0,
            &interning::RequestEvidence::Census {
                hashes: &ControlJson(hashes),
                hash_count: Some(hashes.len() as u64),
            },
        )?;
    }
    Ok(())
}
fn account_proof(s: &mut Scope<'_>, p: &ClaudeAccountFamilyWitness) -> Result<()> {
    s.plain(
        &[],
        0,
        Data::AccountProof {
            account: p.account_identifier_hash.clone(),
            evidence: p.evidence_request_count,
            children: (p.members.len() + p.member_request_id_fingerprints.len()) as u64,
        },
    )?;
    for (m, n) in &p.members {
        s.plain(&["members", m], 0, Data::Number(*n))?;
    }
    for (m, fp) in &p.member_request_id_fingerprints {
        s.plain(&["fingerprints", m], 0, Data::Text(fp.clone()))?;
    }
    Ok(())
}
fn usage_proof(s: &mut Scope<'_>, p: &ClaudeUsageFamilyWitness) -> Result<()> {
    let children = p.member_request_id_fingerprints.len()
        + p.member_occurrence_fingerprints.len()
        + p.assigned_request_id_fingerprints.len()
        + p.legacy_excluded_request_id_hashes.len()
        + p.legacy_owner_roots.len();
    s.plain(
        &[],
        0,
        Data::UsageProof {
            evidence: p.evidence_fingerprint.clone(),
            exclusion: p.legacy_exclusion_evidence_fingerprint.clone(),
            children: children as u64,
        },
    )?;
    for (slot, map) in [
        ("requests", &p.member_request_id_fingerprints),
        ("occurrences", &p.member_occurrence_fingerprints),
        ("assigned", &p.assigned_request_id_fingerprints),
    ] {
        for (m, fp) in map {
            s.plain(&[slot, m], 0, Data::Text(fp.clone()))?;
        }
    }
    for (m, hashes) in &p.legacy_excluded_request_id_hashes {
        s.shared(
            &["excluded", m],
            0,
            &interning::RequestEvidence::Census {
                hashes: &ControlJson(hashes),
                hash_count: Some(hashes.len() as u64),
            },
        )?;
    }
    for m in &p.legacy_owner_roots {
        s.plain(&["owners", m], 0, Data::Empty)?;
    }
    Ok(())
}
fn authority(s: &mut Scope<'_>, p: &ClaudeUsageAuthorityQuarantineRecord) -> Result<()> {
    let owed = p
        .proof_correction
        .as_ref()
        .map_or(0, |c| c.owed_member_ids.len());
    s.plain(
        &[],
        0,
        Data::Authority {
            contract: p.contract.clone(),
            proven: p.proven_witness_fingerprint.clone(),
            failed: p.failed_reconstruction_count,
            disposition: p.disposition,
            retry: p.retry_after_unix_seconds,
            correction: p
                .proof_correction
                .as_ref()
                .map(|c| c.proof_witness_fingerprint.clone()),
            children: (p.member_source_file_fingerprints.len() + owed) as u64,
        },
    )?;
    for (m, fp) in &p.member_source_file_fingerprints {
        s.plain(&["sources", m], 0, Data::Text(fp.clone()))?;
    }
    if let Some(c) = &p.proof_correction {
        for m in &c.owed_member_ids {
            s.plain(&["owed", m], 0, Data::Empty)?;
        }
    }
    Ok(())
}
fn counts(c: &account_pending_retention::Counts) -> [u64; 6] {
    [
        c.roots_collapsed,
        c.windows_collapsed,
        c.window_bytes_saved,
        c.roots_refused,
        c.window_bytes_before,
        c.window_bytes_after,
    ]
}

pub(super) fn populate(
    index: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxAccounts,
) -> Result<()> {
    ensure!(cx.rows.is_empty(), "accounts_populate_nonempty");
    cx.ready = true;
    delta(&ScanIndex::default(), index, txn, cx)
}
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxAccounts,
) -> Result<()> {
    ensure!(cx.ready, "accounts_context_invalid");
    let result = delta_inner(prev, next, txn, cx);
    cx.ready = result.is_ok();
    result
}
fn delta_inner(
    prev: &ScanIndex,
    next: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxAccounts,
) -> Result<()> {
    macro_rules! maps {
        ($field:ident, $kind:expr, $emit:expr) => {{
            let keys: BTreeSet<_> = prev.$field.keys().chain(next.$field.keys()).collect();
            for family in keys {
                if prev.$field.get(family) == next.$field.get(family) {
                    continue;
                }
                scope(txn, cx, $kind, family, |s| {
                    if let Some(p) = next.$field.get(family) {
                        ($emit)(s, p)?;
                    }
                    Ok(())
                })?;
            }
        }};
    }
    let families: BTreeSet<_> = prev
        .claude_account_family_pending
        .keys()
        .chain(next.claude_account_family_pending.keys())
        .collect();
    for family in families {
        if prev.claude_account_family_pending.get(family)
            != next.claude_account_family_pending.get(family)
        {
            windows(
                prev.claude_account_family_pending.get(family),
                next.claude_account_family_pending.get(family),
                family,
                txn,
                cx,
            )?;
        }
    }
    maps!(claude_usage_family_pending, "usage.pending", usage);
    maps!(
        claude_usage_family_pending,
        "family.requests",
        |s: &mut Scope<'_>, p: &ClaudeUsageFamilyPending| request_map(
            s,
            &p.member_request_id_hashes
        )
    );
    maps!(
        claude_account_family_witnesses,
        "proof.account",
        account_proof
    );
    maps!(claude_usage_family_witnesses, "proof.usage", usage_proof);
    maps!(
        claude_usage_authority_quarantine,
        "refusal.authority",
        authority
    );
    maps!(
        claude_account_deferred_holds,
        "proof.deferred_account",
        |s: &mut Scope<'_>, p: &String| s.plain(&[], 0, Data::Text(p.clone()))
    );
    maps!(
        session_account_bindings,
        "setting.binding",
        |s: &mut Scope<'_>, p: &SessionAccountBinding| s.plain(&[], 0, Data::Binding(p.clone()))
    );
    // This v1 field is serde(skip): retain diagnostic counts separately and
    // never make their presence an attribution or retirement input.
    if !cx.rows.contains_key(&(RETENTION.into(), String::new()))
        || counts(&prev.claude_account_window_retention)
            != counts(&next.claude_account_window_retention)
    {
        scope(txn, cx, RETENTION, "", |s| {
            s.plain(
                &[],
                0,
                Data::Retention(counts(&next.claude_account_window_retention)),
            )
        })?;
    }
    Ok(())
}

// Evidence is decoded directly, bypassing v1's normalizing account decoder.
// Malformed/unrecognized encodings refuse hydration, never fabricate an empty set.
fn evidence(tx: &mut dyn Transaction, id: u64) -> Result<Vec<u8>> {
    let h = tx
        .get(&RowKey::RequestSet(id))?
        .context("accounts_reference_missing")?;
    ensure!(
        matches!(h.fixed, Fixed::RequestSet { .. }) && h.value_version == 1 && h.len <= VALUE_BYTES,
        "accounts_reference_shape"
    );
    let mut bytes = Vec::new();
    tx.read_value(
        &h,
        &mut Limited {
            out: &mut bytes,
            cap: VALUE_BYTES,
        },
    )?;
    Ok(bytes)
}
struct Evidence<'a>(&'a [u8]);
impl<'a> Evidence<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "accounts_evidence_shape");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = usize::try_from(self.number()?)?;
        self.take(n)
    }
    fn text(&mut self) -> Result<String> {
        Ok(std::str::from_utf8(self.bytes()?)?.to_owned())
    }
    fn start(&mut self) -> Result<Option<u64>> {
        ensure!(self.byte()? == 1, "accounts_evidence_version");
        Ok(match self.byte()? {
            0 => None,
            1 => Some(self.number()?),
            _ => bail!("accounts_evidence_shape"),
        })
    }
}
fn account_set(tx: &mut dyn Transaction, id: u64) -> Result<ClaudeAccountRequestSet> {
    let bytes = evidence(tx, id)?;
    let mut r = Evidence(&bytes);
    ensure!(
        r.start()?.is_none() && r.byte()? == 1,
        "accounts_evidence_class"
    );
    let prefixes = r.text()?;
    let fingerprint = r.text()?;
    let identity_revision = match r.byte()? {
        0 => None,
        1 => Some(r.text()?),
        _ => bail!("accounts_evidence_shape"),
    };
    ensure!(
        r.0.is_empty()
            && fingerprint.len() <= KEY_BYTES
            && identity_revision
                .as_ref()
                .map_or(true, |s| s.len() <= KEY_BYTES),
        "accounts_evidence_shape"
    );
    Ok(ClaudeAccountRequestSet {
        prefixes,
        fingerprint,
        identity_revision,
    })
}
fn full_set(tx: &mut dyn Transaction, id: u64) -> Result<BTreeSet<String>> {
    let bytes = evidence(tx, id)?;
    let mut r = Evidence(&bytes);
    let count = r.start()?.context("accounts_evidence_count")?;
    ensure!(r.byte()? == 2, "accounts_evidence_class");
    let hashes: BTreeSet<String> = serde_json::from_slice(r.bytes()?)?;
    ensure!(
        r.0.is_empty()
            && hashes.len() as u64 == count
            && hashes.iter().all(|s| s.len() <= KEY_BYTES),
        "accounts_evidence_shape"
    );
    Ok(hashes)
}
fn active_window<'a>(
    out: &'a mut ScanIndex,
    slots: &BTreeMap<(String, u64), Option<usize>>,
    family: &str,
    id: u64,
) -> Result<&'a mut ClaudeAccountFamilyPendingWindow> {
    let slot = slots
        .get(&(family.to_owned(), id))
        .context("accounts_window_missing")?;
    let p = out
        .claude_account_family_pending
        .get_mut(family)
        .context("accounts_family_missing")?;
    Ok(if let Some(at) = slot {
        p.previous_windows
            .get_mut(*at)
            .context("accounts_window_missing")?
    } else {
        &mut p.current
    })
}

/// Store has a generic associated transaction type and needs mutable begin;
/// consequently the brief's `&dyn Store` is not a legal Rust interface.
pub(super) fn hydrate(
    store: &mut impl Store,
    index: &mut ScanIndex,
    cx: &mut KindCxAccounts,
) -> Result<()> {
    cx.ready = false;
    let mut tx = store.begin(TxnMode::Read)?;
    let mut out = ScanIndex::default();
    let mut staged = KindCxAccounts::default();
    let mut pointers = BTreeMap::<String, (Option<u64>, u64)>::new();
    let mut slots = BTreeMap::new();
    let mut inventory = BTreeMap::<(String, String, u64), (Option<u64>, u64)>::new();
    for kind in KINDS {
        let parsed = RecordKind::parse(kind)?;
        let mut after = None;
        loop {
            let page = tx.scan_kind(&parsed, after.as_ref(), 64)?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|h| h.key.clone());
            for h in page {
                let RowKey::Record {
                    key_bytes,
                    position,
                    ..
                } = &h.key
                else {
                    bail!("accounts_row_kind")
                };
                let position = *position;
                let components = decode(key_bytes)?;
                let family = &components[0];
                let part = read(&mut tx, &h)?;
                part.data.texts(&mut |s| {
                    ensure!(s.len() <= KEY_BYTES, "state_v2_string_admission");
                    Ok(())
                })?;
                ensure!(
                    part.path == components[1..],
                    "accounts_key_payload_mismatch"
                );
                let path: Vec<_> = part.path.iter().map(String::as_str).collect();
                let root = path.is_empty();
                let state = inventory
                    .entry(((*kind).into(), family.clone(), position))
                    .or_default();
                if root {
                    ensure!(state.0.is_none(), "accounts_duplicate_root");
                    state.0 = Some(part.data.children().unwrap_or_else(|| {
                        if matches!(*kind, "account.absent_members" | "family.requests") {
                            if let Data::Number(n) = part.data {
                                return n;
                            }
                        }
                        0
                    }));
                } else {
                    state.1 += 1;
                }
                match (*kind, path.as_slice(), part.data) {
                    ("account.current", [], Data::Current { current, next }) => {
                        ensure!(
                            position == 0
                                && next > 0
                                && next <= i64::MAX as u64 + 1
                                && current.map_or(true, |id| id > 0 && id < next),
                            "accounts_high_water"
                        );
                        pointers.insert(family.clone(), (current, next));
                        if current.is_some() {
                            out.claude_account_family_pending.insert(
                                family.clone(),
                                ClaudeAccountFamilyPending {
                                    current: blank_window(),
                                    previous_windows: Vec::new(),
                                    confirmed_absent_members: BTreeSet::new(),
                                },
                            );
                        }
                    }
                    (
                        "account_window",
                        [],
                        Data::Window {
                            version,
                            boundary,
                            account,
                            evidence,
                            complete,
                            invalid,
                            ..
                        },
                    ) => {
                        let (current, next) =
                            pointers.get(family).context("accounts_pointer_missing")?;
                        let current = current.context("accounts_pointer_empty")?;
                        ensure!(
                            position > 0 && position < *next && position <= current,
                            "accounts_window_order"
                        );
                        let p = out
                            .claude_account_family_pending
                            .get_mut(family)
                            .context("accounts_family_missing")?;
                        let w = ClaudeAccountFamilyPendingWindow {
                            version,
                            census_window_end: boundary,
                            account_identifier_hash: account,
                            evidence_request_count: evidence,
                            census_complete: complete,
                            invalid,
                            members: BTreeMap::new(),
                            member_requests: BTreeMap::new(),
                        };
                        let slot = if current == position {
                            p.current = w;
                            None
                        } else {
                            let at = p.previous_windows.len();
                            p.previous_windows.push(w);
                            Some(at)
                        };
                        ensure!(
                            slots.insert((family.clone(), position), slot).is_none(),
                            "accounts_duplicate_window"
                        );
                    }
                    ("account_window", ["members", m], Data::Number(n)) => {
                        active_window(&mut out, &slots, family, position)?
                            .members
                            .insert((*m).into(), n);
                    }
                    ("account_window", ["requests", m], Data::Shared(id)) => {
                        let set = account_set(&mut tx, id)?;
                        active_window(&mut out, &slots, family, position)?
                            .member_requests
                            .insert((*m).into(), set);
                    }
                    ("account.absent_members", [], Data::Number(_)) => {
                        ensure!(
                            position == 0 && out.claude_account_family_pending.contains_key(family),
                            "accounts_family_missing"
                        );
                    }
                    ("account.absent_members", [m], Data::Empty) => {
                        out.claude_account_family_pending
                            .get_mut(family)
                            .context("accounts_family_missing")?
                            .confirmed_absent_members
                            .insert((*m).into());
                    }
                    (
                        "usage.pending",
                        [],
                        Data::Usage {
                            boundary,
                            invalid,
                            idless,
                            ..
                        },
                    ) => {
                        out.claude_usage_family_pending.insert(
                            family.clone(),
                            ClaudeUsageFamilyPending {
                                census_window_end: boundary,
                                member_request_id_hashes: BTreeMap::new(),
                                member_occurrences: BTreeMap::new(),
                                invalid,
                                idless_revision: idless,
                            },
                        );
                    }
                    ("usage.pending", [m], Data::Empty) => {
                        out.claude_usage_family_pending
                            .get_mut(family)
                            .context("accounts_usage_missing")?
                            .member_occurrences
                            .insert((*m).into(), BTreeMap::new());
                    }
                    ("usage.pending", [m, r], Data::Occurrence(o)) => {
                        out.claude_usage_family_pending
                            .get_mut(family)
                            .context("accounts_usage_missing")?
                            .member_occurrences
                            .get_mut(*m)
                            .context("accounts_member_missing")?
                            .insert((*r).into(), o);
                    }
                    ("family.requests", [], Data::Number(_)) => {
                        ensure!(
                            out.claude_usage_family_pending.contains_key(family),
                            "accounts_usage_missing"
                        );
                    }
                    ("family.requests", [m], Data::Shared(id)) => {
                        let set = full_set(&mut tx, id)?;
                        out.claude_usage_family_pending
                            .get_mut(family)
                            .context("accounts_usage_missing")?
                            .member_request_id_hashes
                            .insert((*m).into(), set);
                    }
                    (
                        "proof.account",
                        [],
                        Data::AccountProof {
                            account, evidence, ..
                        },
                    ) => {
                        out.claude_account_family_witnesses.insert(
                            family.clone(),
                            ClaudeAccountFamilyWitness {
                                account_identifier_hash: account,
                                evidence_request_count: evidence,
                                members: BTreeMap::new(),
                                member_request_id_fingerprints: BTreeMap::new(),
                            },
                        );
                    }
                    ("proof.account", ["members", m], Data::Number(n)) => {
                        out.claude_account_family_witnesses
                            .get_mut(family)
                            .context("accounts_proof_missing")?
                            .members
                            .insert((*m).into(), n);
                    }
                    ("proof.account", ["fingerprints", m], Data::Text(fp)) => {
                        out.claude_account_family_witnesses
                            .get_mut(family)
                            .context("accounts_proof_missing")?
                            .member_request_id_fingerprints
                            .insert((*m).into(), fp);
                    }
                    (
                        "proof.usage",
                        [],
                        Data::UsageProof {
                            evidence,
                            exclusion,
                            ..
                        },
                    ) => {
                        out.claude_usage_family_witnesses.insert(
                            family.clone(),
                            ClaudeUsageFamilyWitness {
                                evidence_fingerprint: evidence,
                                member_request_id_fingerprints: BTreeMap::new(),
                                member_occurrence_fingerprints: BTreeMap::new(),
                                assigned_request_id_fingerprints: BTreeMap::new(),
                                legacy_excluded_request_id_hashes: BTreeMap::new(),
                                legacy_exclusion_evidence_fingerprint: exclusion,
                                legacy_owner_roots: BTreeSet::new(),
                            },
                        );
                    }
                    (
                        "proof.usage",
                        [slot @ ("requests" | "occurrences" | "assigned"), m],
                        Data::Text(fp),
                    ) => {
                        let p = out
                            .claude_usage_family_witnesses
                            .get_mut(family)
                            .context("accounts_proof_missing")?;
                        let map = match *slot {
                            "requests" => &mut p.member_request_id_fingerprints,
                            "occurrences" => &mut p.member_occurrence_fingerprints,
                            _ => &mut p.assigned_request_id_fingerprints,
                        };
                        map.insert((*m).into(), fp);
                    }
                    ("proof.usage", ["excluded", m], Data::Shared(id)) => {
                        let set = full_set(&mut tx, id)?;
                        out.claude_usage_family_witnesses
                            .get_mut(family)
                            .context("accounts_proof_missing")?
                            .legacy_excluded_request_id_hashes
                            .insert((*m).into(), set);
                    }
                    ("proof.usage", ["owners", m], Data::Empty) => {
                        out.claude_usage_family_witnesses
                            .get_mut(family)
                            .context("accounts_proof_missing")?
                            .legacy_owner_roots
                            .insert((*m).into());
                    }
                    ("proof.deferred_account", [], Data::Text(fp)) => {
                        out.claude_account_deferred_holds.insert(family.clone(), fp);
                    }
                    ("setting.binding", [], Data::Binding(binding)) => {
                        out.session_account_bindings.insert(family.clone(), binding);
                    }
                    (
                        "refusal.authority",
                        [],
                        Data::Authority {
                            contract,
                            proven,
                            failed,
                            disposition,
                            retry,
                            correction,
                            ..
                        },
                    ) => {
                        out.claude_usage_authority_quarantine.insert(
                            family.clone(),
                            ClaudeUsageAuthorityQuarantineRecord {
                                contract,
                                proven_witness_fingerprint: proven,
                                failed_reconstruction_count: failed,
                                disposition,
                                retry_after_unix_seconds: retry,
                                member_source_file_fingerprints: BTreeMap::new(),
                                proof_correction: correction.map(|proof| {
                                    ClaudeAuthorityProofCorrection {
                                        proof_witness_fingerprint: proof,
                                        owed_member_ids: BTreeSet::new(),
                                    }
                                }),
                            },
                        );
                    }
                    ("refusal.authority", ["sources", m], Data::Text(fp)) => {
                        out.claude_usage_authority_quarantine
                            .get_mut(family)
                            .context("accounts_authority_missing")?
                            .member_source_file_fingerprints
                            .insert((*m).into(), fp);
                    }
                    ("refusal.authority", ["owed", m], Data::Empty) => {
                        out.claude_usage_authority_quarantine
                            .get_mut(family)
                            .context("accounts_authority_missing")?
                            .proof_correction
                            .as_mut()
                            .context("accounts_correction_missing")?
                            .owed_member_ids
                            .insert((*m).into());
                    }
                    (RETENTION, [], Data::Retention(c)) => {
                        ensure!(family.is_empty(), "accounts_retention_shape");
                        out.claude_account_window_retention = account_pending_retention::Counts {
                            roots_collapsed: c[0],
                            windows_collapsed: c[1],
                            window_bytes_saved: c[2],
                            roots_refused: c[3],
                            window_bytes_before: c[4],
                            window_bytes_after: c[5],
                        };
                    }
                    _ => bail!("accounts_bucket_shape"),
                }
                ensure!(
                    *kind == "account_window" || position == 0,
                    "accounts_position_shape"
                );
                staged
                    .rows
                    .entry(((*kind).into(), family.clone()))
                    .or_default()
                    .insert(h.key.clone(), h);
            }
        }
    }
    ensure!(
        inventory
            .values()
            .all(|(expected, actual)| *expected == Some(*actual)),
        "accounts_bucket_inventory"
    );
    for (family, (current, _)) in &pointers {
        if let Some(id) = current {
            ensure!(
                slots.contains_key(&(family.clone(), *id))
                    && staged
                        .rows
                        .contains_key(&("account.absent_members".into(), family.clone())),
                "accounts_current_missing"
            );
            let p = &out.claude_account_family_pending[family];
            if p.previous_windows.len() + 1 > 64 {
                staged.families_over_64_windows += 1;
            }
        }
    }
    for family in out.claude_usage_family_pending.keys() {
        ensure!(
            staged
                .rows
                .contains_key(&("family.requests".into(), family.clone())),
            "accounts_requests_missing"
        );
    }
    // A projection is a cache of these exact semantic fields, never another
    // authority. Check it after all independent maps have been reconstructed.
    for ((kind, family), rows) in &staged.rows {
        for h in rows.values() {
            let RowKey::Record {
                key_bytes,
                position,
                ..
            } = &h.key
            else {
                bail!("accounts_row_kind")
            };
            let root = decode(key_bytes)?.len() == 1;
            let expected = match (kind.as_str(), root) {
                ("account_window", true) => {
                    let w = active_window(&mut out, &slots, family, *position)?;
                    Fixed::AccountPending {
                        account_hash: canonical_hash(&w.account_identifier_hash),
                        evidence_count: w.evidence_request_count,
                        flags: 1
                            | (u64::from(w.census_complete) << 1)
                            | (u64::from(w.invalid) << 2),
                        member_count: w.members.len() as u64,
                        set_count: w.member_requests.len() as u64,
                    }
                }
                ("account_window", false) => Fixed::AccountPending {
                    account_hash: None,
                    evidence_count: 0,
                    flags: 1 << 63,
                    member_count: 0,
                    set_count: 0,
                },
                ("usage.pending", true) => {
                    let p = &out.claude_usage_family_pending[family];
                    Fixed::UsagePending {
                        flags: 1 | (u64::from(p.invalid) << 1),
                        idless_revision: p.idless_revision,
                        occurrence_count: p
                            .member_occurrences
                            .values()
                            .map(BTreeMap::len)
                            .sum::<usize>() as u64,
                        member_count: p.member_occurrences.len() as u64,
                    }
                }
                ("usage.pending", false) => Fixed::UsagePending {
                    flags: 1 << 63,
                    idless_revision: None,
                    occurrence_count: 0,
                    member_count: 0,
                },
                _ => Fixed::None,
            };
            ensure!(h.fixed == expected, "accounts_projection_mismatch");
        }
    }
    ensure!(
        staged.rows.contains_key(&(RETENTION.into(), String::new())),
        "accounts_retention_missing"
    );
    staged.ready = true;
    index.claude_account_family_pending = out.claude_account_family_pending;
    index.claude_account_family_witnesses = out.claude_account_family_witnesses;
    index.claude_usage_family_pending = out.claude_usage_family_pending;
    index.claude_usage_family_witnesses = out.claude_usage_family_witnesses;
    index.claude_account_window_retention = out.claude_account_window_retention;
    index.claude_account_deferred_holds = out.claude_account_deferred_holds;
    index.session_account_bindings = out.session_account_bindings;
    index.claude_usage_authority_quarantine = out.claude_usage_authority_quarantine;
    *cx = staged;
    Ok(())
}

/// Complete references, including repeated edges in different buckets. Shared
/// evidence has no outgoing references. Integrator dispatches by KINDS.
pub(super) fn references(
    h: &Header,
    value: &dyn Value,
    refs: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    if !matches!(h.key, RowKey::Record { .. }) {
        return Ok(());
    }
    if let Some(id) = ref_id(&unpack(value)?) {
        refs(&RowKey::RequestSet(id))?;
    }
    Ok(())
}
/// Family/member/request keys can contain opaque legacy paths. These keys are
/// PL under the source contract even when their current spelling is hash-like.
/// Values retain opaque literals too; emit them before erasure comparisons.
pub(super) fn private_paths(
    h: &Header,
    value: &dyn Value,
    paths: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let RowKey::Record { key_bytes, .. } = &h.key else {
        return Ok(());
    };
    for text in decode(key_bytes)? {
        paths(&text)?;
    }
    let part = unpack(value)?;
    part.data.texts(paths)
}
impl Data {
    fn texts(&self, emit: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
        match self {
            Self::Window {
                version,
                boundary,
                account,
                ..
            } => {
                emit(version)?;
                emit(boundary)?;
                emit(account)?;
            }
            Self::Usage { boundary, .. } => emit(boundary)?,
            Self::AccountProof { account, .. } => emit(account)?,
            Self::UsageProof {
                evidence,
                exclusion,
                ..
            } => {
                emit(evidence)?;
                if let Some(s) = exclusion {
                    emit(s)?;
                }
            }
            Self::Authority {
                contract,
                proven,
                correction,
                ..
            } => {
                emit(contract)?;
                emit(proven)?;
                if let Some(s) = correction {
                    emit(s)?;
                }
            }
            Self::Binding(b) => {
                emit(&b.account_identifier_hash)?;
                if let Some(s) = &b.workspace_identifier_hash {
                    emit(s)?;
                }
            }
            Self::Text(s) => emit(s)?,
            Self::Occurrence(o) => {
                for s in [&o.model, &o.speed_mode, &o.reasoning_effort]
                    .into_iter()
                    .flatten()
                {
                    emit(s)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);
    impl Scratch {
        fn store() -> (Self, sqlite::Sqlite) {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ottto-accounts-mapper-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            let mut db =
                sqlite::Sqlite::create_import(&dir.join("index.v2.sqlite.import")).unwrap();
            db.path_extractor(private_paths);
            db.reference_extractor(references);
            db.control(
                "identity",
                &Identity {
                    format: FORMAT,
                    db_id: "synthetic-accounts".into(),
                    binding: super::super::super::scan_index_persistence::Binding {
                        source: super::super::super::scan_index_persistence::Source::Claude,
                        namespace_hash: "a".repeat(64),
                    },
                    fence_generation: 0,
                },
            )
            .unwrap();
            db.control("generation", &0_u64).unwrap();
            (Self(dir), db)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn save(
        db: &mut impl Store,
        prev: Option<&ScanIndex>,
        next: &ScanIndex,
        cx: &mut KindCxAccounts,
        generation: u64,
    ) {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        match prev {
            Some(prev) => delta(prev, next, &mut tx, cx).unwrap(),
            None => populate(next, &mut tx, cx).unwrap(),
        }
        assert_eq!(
            tx.commit(generation, generation + 1),
            DurableCommitOutcome::Committed(generation + 1)
        );
    }
    fn window(boundary: &str) -> ClaudeAccountFamilyPendingWindow {
        let mut w = blank_window();
        w.version = super::super::super::CLAUDE_ACCOUNT_REQUEST_SET_VERSION.into();
        w.census_window_end = boundary.into();
        w.account_identifier_hash = "a".repeat(64);
        // Independent maps, including a member with no request-set entry.
        w.evidence_request_count = u128::MAX;
        w.members.insert("/opaque/member".into(), u64::MAX);
        w.member_requests.insert(
            "/opaque/requests-only".into(),
            ClaudeAccountRequestSet {
                prefixes: String::new(),
                fingerprint: "b".repeat(64),
                identity_revision: Some("c".repeat(64)),
            },
        );
        w.invalid = true;
        w
    }
    fn graph() -> ScanIndex {
        let mut index = ScanIndex::default();
        index.claude_account_family_pending.insert(
            "family".into(),
            ClaudeAccountFamilyPending {
                current: window("exact boundary"),
                previous_windows: vec![window("not normalized")],
                confirmed_absent_members: BTreeSet::from(["/opaque/absent".into()]),
            },
        );
        index.claude_account_family_witnesses.insert(
            "family".into(),
            ClaudeAccountFamilyWitness {
                account_identifier_hash: "A".repeat(64),
                evidence_request_count: u128::MAX,
                members: BTreeMap::from([("left".into(), u64::MAX)]),
                member_request_id_fingerprints: BTreeMap::from([(
                    "independent".into(),
                    String::new(),
                )]),
            },
        );
        index.claude_usage_family_pending.insert(
            "family".into(),
            ClaudeUsageFamilyPending {
                census_window_end: "2026-10-30T16:01:02.000+03:00".into(),
                member_request_id_hashes: BTreeMap::from([
                    ("empty".into(), BTreeSet::new()),
                    ("hashes".into(), BTreeSet::from(["d".repeat(64)])),
                ]),
                member_occurrences: BTreeMap::from([
                    ("empty".into(), BTreeMap::new()),
                    (
                        "occurrence-only".into(),
                        BTreeMap::from([(
                            "/opaque/request".into(),
                            ClaudeTranscriptUsageOccurrenceWitness {
                                sequence: u64::MAX,
                                input_tokens: u64::MAX,
                                output_tokens: u64::MAX,
                                cache_read_tokens: u64::MAX,
                                cache_creation_5m_tokens: u64::MAX,
                                cache_creation_1h_tokens: u64::MAX,
                                reasoning_output_tokens: u64::MAX,
                                model: Some(String::new()),
                                speed_mode: None,
                                reasoning_effort: Some("literal".into()),
                            },
                        )]),
                    ),
                ]),
                invalid: true,
                idless_revision: Some([0; 32]),
            },
        );
        index.claude_usage_family_witnesses.insert(
            "family".into(),
            ClaudeUsageFamilyWitness {
                evidence_fingerprint: "e".repeat(64),
                member_request_id_fingerprints: BTreeMap::from([("a".into(), "f".repeat(64))]),
                member_occurrence_fingerprints: BTreeMap::from([("b".into(), "0".repeat(64))]),
                assigned_request_id_fingerprints: BTreeMap::from([("c".into(), "1".repeat(64))]),
                legacy_excluded_request_id_hashes: BTreeMap::from([(
                    "empty".into(),
                    BTreeSet::new(),
                )]),
                legacy_exclusion_evidence_fingerprint: Some(String::new()),
                legacy_owner_roots: BTreeSet::from(["/opaque/owner".into()]),
            },
        );
        index.claude_usage_authority_quarantine.insert(
            "family".into(),
            ClaudeUsageAuthorityQuarantineRecord {
                contract: "claude_usage_authority_quarantine:v2".into(),
                proven_witness_fingerprint: "2".repeat(64),
                member_source_file_fingerprints: BTreeMap::from([(
                    "/opaque/source".into(),
                    "3".repeat(64),
                )]),
                failed_reconstruction_count: 0,
                disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
                retry_after_unix_seconds: u64::MAX,
                proof_correction: Some(ClaudeAuthorityProofCorrection {
                    proof_witness_fingerprint: "4".repeat(64),
                    owed_member_ids: BTreeSet::new(),
                }),
            },
        );
        index
            .claude_account_deferred_holds
            .insert("/opaque/deferred".into(), String::new());
        index.session_account_bindings.insert(
            String::new(),
            SessionAccountBinding {
                account_identifier_hash: "5".repeat(64),
                workspace_identifier_hash: Some(String::new()),
            },
        );
        index.session_account_bindings.insert(
            "none".into(),
            SessionAccountBinding {
                account_identifier_hash: "5".repeat(64),
                workspace_identifier_hash: None,
            },
        );
        index.claude_account_window_retention.windows_collapsed = 11;
        index
    }
    fn assert_subset(a: &ScanIndex, b: &ScanIndex) {
        macro_rules! same { ($($field:ident),*) => { $(assert_eq!(serde_json::to_vec(&a.$field).unwrap(), serde_json::to_vec(&b.$field).unwrap(), stringify!($field));)* }; }
        same!(
            claude_account_family_pending,
            claude_account_family_witnesses,
            claude_usage_family_pending,
            claude_usage_family_witnesses,
            claude_usage_authority_quarantine,
            claude_account_deferred_holds,
            session_account_bindings
        );
        assert_eq!(
            counts(&a.claude_account_window_retention),
            counts(&b.claude_account_window_retention)
        );
    }
    #[test]
    fn typed_round_trip_preserves_independent_maps_u128_u64_and_optional_empty() {
        let (_scratch, mut db) = Scratch::store();
        let a = graph();
        let mut cx = KindCxAccounts::default();
        save(&mut db, None, &a, &mut cx, 0);
        let mut b = ScanIndex::default();
        hydrate(&mut db, &mut b, &mut KindCxAccounts::default()).unwrap();
        assert_subset(&a, &b);
    }
    #[test]
    fn original_v1_fixture_populate_hydrate_subset_bytes() {
        let a: ScanIndex = serde_json::from_str(include_str!(
            "../../../tests/fixtures/scan_index/real-shaped-v1.json"
        ))
        .unwrap();
        let (_scratch, mut db) = Scratch::store();
        save(&mut db, None, &a, &mut KindCxAccounts::default(), 0);
        let mut b = ScanIndex::default();
        hydrate(&mut db, &mut b, &mut KindCxAccounts::default()).unwrap();
        assert_subset(&a, &b);
    }
    fn positions(cx: &KindCxAccounts) -> Vec<u64> {
        let rows = &cx.rows[&("account_window".into(), "family".into())];
        rows.keys()
            .filter_map(|k| match k {
                RowKey::Record {
                    key_bytes,
                    position,
                    ..
                } if decode(key_bytes).unwrap().len() == 1 => Some(*position),
                _ => None,
            })
            .collect()
    }
    #[test]
    fn middle_retirement_restart_and_family_recreation_never_reuse_ids() {
        let (_scratch, mut db) = Scratch::store();
        let mut a = graph();
        a.claude_account_family_pending
            .get_mut("family")
            .unwrap()
            .previous_windows = vec![window("A"), window("B"), window("C")];
        let mut cx = KindCxAccounts::default();
        save(&mut db, None, &a, &mut cx, 0);
        assert_eq!(positions(&cx), [1, 2, 3, 4]);
        let mut b = a.clone();
        b.claude_account_family_pending
            .get_mut("family")
            .unwrap()
            .previous_windows
            .remove(1);
        save(&mut db, Some(&a), &b, &mut cx, 1);
        assert_eq!(positions(&cx), [1, 3, 4]);
        let mut restart = ScanIndex::default();
        hydrate(&mut db, &mut restart, &mut cx).unwrap();
        assert_subset(&b, &restart);
        let mut c = b.clone();
        c.claude_account_family_pending.clear();
        save(&mut db, Some(&b), &c, &mut cx, 2);
        hydrate(&mut db, &mut restart, &mut cx).unwrap();
        assert!(restart.claude_account_family_pending.is_empty());
        save(&mut db, Some(&c), &a, &mut cx, 3);
        assert_eq!(positions(&cx), [5, 6, 7, 8]);
    }
    #[test]
    fn erasure_covers_path_bearing_keys_and_literals_and_refs_are_exact() {
        let k = key(
            "proof.deferred_account",
            "/opaque/family",
            &["/opaque/member"],
            0,
        )
        .unwrap();
        let value = Part {
            path: vec!["/opaque/member".into()],
            data: Data::Text("/opaque/value".into()),
        };
        let h = preflight(&RowInput {
            key: &k,
            fixed: &Fixed::None,
            value_version: 1,
            value: &packed::Json(&value),
        })
        .unwrap();
        let mut paths = BTreeSet::new();
        private_paths(&h, &packed::Json(&value), &mut |p| {
            paths.insert(p.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            paths,
            BTreeSet::from([
                "/opaque/family".into(),
                "/opaque/member".into(),
                "/opaque/value".into()
            ])
        );
        let part = Part {
            path: vec![],
            data: Data::Shared(7),
        };
        let mut refs = Vec::new();
        references(&h, &packed::Json(&part), &mut |key| {
            refs.push(key.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(refs, [RowKey::RequestSet(7)]);
    }
    #[test]
    fn absent_empty_and_alarm_preserve_all_custody() {
        let (_scratch, mut db) = Scratch::store();
        let mut a = ScanIndex::default();
        a.claude_account_family_pending.insert(
            "family".into(),
            ClaudeAccountFamilyPending {
                current: window("current"),
                previous_windows: (0..65).map(|n| window(&format!("window-{n}"))).collect(),
                confirmed_absent_members: BTreeSet::new(),
            },
        );
        a.claude_usage_family_pending.insert(
            "empty".into(),
            ClaudeUsageFamilyPending {
                census_window_end: String::new(),
                member_request_id_hashes: BTreeMap::new(),
                member_occurrences: BTreeMap::new(),
                invalid: false,
                idless_revision: None,
            },
        );
        let mut cx = KindCxAccounts::default();
        save(&mut db, None, &a, &mut cx, 0);
        assert_eq!(cx.families_over_64_windows, 1);
        assert_eq!(positions(&cx).len(), 66);
        let mut b = ScanIndex::default();
        hydrate(&mut db, &mut b, &mut cx).unwrap();
        assert_subset(&a, &b);
        assert!(!b.claude_usage_family_pending.contains_key("absent"));
    }
    #[test]
    fn delta_rewrites_only_the_changed_typed_bucket() {
        let (_scratch, mut db) = Scratch::store();
        let a = graph();
        let mut cx = KindCxAccounts::default();
        save(&mut db, None, &a, &mut cx, 0);
        let stats = |db: &sqlite::Sqlite| {
            serde_json::to_value(db.maintenance_stats()).unwrap()["row_write_attempts"]
                .as_u64()
                .unwrap()
        };
        let before = stats(&db);
        {
            let mut tx = db.begin(TxnMode::Read).unwrap();
            delta(&a, &a, &mut tx, &mut cx).unwrap();
        }
        assert_eq!(stats(&db), before);
        let mut b = a.clone();
        b.claude_account_family_pending
            .get_mut("family")
            .unwrap()
            .current
            .members
            .insert("/opaque/member".into(), 42);
        let before_rows = cx.rows.clone();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        delta(&a, &b, &mut tx, &mut cx).unwrap();
        // Drop the borrow to inspect write attempts, deliberately without a
        // commit (which also writes generation/capability/erasure controls).
        drop(tx);
        assert_eq!(stats(&db) - before, 1);
        let changed: Vec<_> = cx
            .rows
            .iter()
            .flat_map(|(owner, rows)| {
                rows.iter()
                    .filter(|(k, h)| before_rows[owner].get(*k) != Some(*h))
                    .map(|(k, _)| k.clone())
            })
            .collect();
        assert_eq!(
            changed,
            [key(
                "account_window",
                "family",
                &["members", "/opaque/member"],
                2
            )
            .unwrap()]
        );
    }
    #[test]
    fn large_family_fragments_are_stable_small_and_shared_counts_reclaim() {
        let (_scratch, mut db) = Scratch::store();
        let mut a = graph();
        let p = a.claude_usage_family_pending.get_mut("family").unwrap();
        p.member_request_id_hashes = (0..400)
            .map(|n| (format!("member-{n:04}"), BTreeSet::from(["d".repeat(64)])))
            .collect();
        let mut cx = KindCxAccounts::default();
        save(&mut db, None, &a, &mut cx, 0);
        assert!(cx
            .rows
            .values()
            .flat_map(BTreeMap::values)
            .all(|h| h.len <= TARGET));
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let sets = tx
            .scan_prefix(
                RowPrefix {
                    table: Table::RequestSets,
                },
                None,
                64,
            )
            .unwrap();
        assert!(sets
            .iter()
            .any(|h| matches!(h.fixed, Fixed::RequestSet { refs: 400, .. })));
        drop(tx);
        let mut b = a.clone();
        b.claude_usage_family_pending.clear();
        b.claude_usage_family_witnesses.clear();
        save(&mut db, Some(&a), &b, &mut cx, 1);
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let remaining = tx
            .scan_prefix(
                RowPrefix {
                    table: Table::RequestSets,
                },
                None,
                64,
            )
            .unwrap();
        // Two account windows still reference their shared account evidence.
        assert_eq!(remaining.len(), 1);
        assert!(matches!(
            remaining[0].fixed,
            Fixed::RequestSet { refs: 2, .. }
        ));
    }
    #[test]
    fn missing_bucket_holds_without_partially_publishing_hydration() {
        let (_scratch, mut db) = Scratch::store();
        let a = graph();
        let mut cx = KindCxAccounts::default();
        save(&mut db, None, &a, &mut cx, 0);
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.delete(
            &key(
                "account_window",
                "family",
                &["members", "/opaque/member"],
                2,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        let mut b = graph();
        b.claude_account_deferred_holds
            .insert("sentinel".into(), "kept".into());
        let before = b.clone();
        assert!(hydrate(&mut db, &mut b, &mut cx).is_err());
        assert_subset(&before, &b);
        assert!(!cx.ready);
    }
    #[test]
    fn canonical_components_do_not_alias_empty_nul_or_prefixes() {
        let keys = [
            vec!["a", "b"],
            vec!["a\0b"],
            vec!["", "a"],
            vec!["a", ""],
            vec!["ab"],
        ];
        let encoded: BTreeSet<_> = keys.iter().map(|k| encode(k).unwrap()).collect();
        assert_eq!(encoded.len(), keys.len());
        for parts in keys {
            assert_eq!(decode(&encode(&parts).unwrap()).unwrap(), parts);
        }
    }
}
