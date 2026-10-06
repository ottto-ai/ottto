//! Local proof for joining physical Codex rollouts. Requested-tier selectors
//! retain the existing reader's meaning; response ownership is a separate fact.
use super::*;

pub(super) const MAX_MEMBERS: usize = 32;
pub(super) const MAX_RECORDS: usize = 50_000;
pub(super) const MAX_HEADER_BYTES: usize = 64 * 1024;

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
        if string_eq_at(value, &["type"], "token_usage_record") {
            if self.observe_response(value).is_none() {
                self.invalid = true;
            }
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
mod tests {
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
