//! Slot-scoped proof from the file's ordinary owned read. No email or new
//! email digest enters a reduction, checkpoint, index, wire body or diagnostic.
use super::*;

pub(crate) const CONTRACT: &str = "session_slot_owner:v1";
// Empirical receiver-neutral continuity evidence: respectively 24, 26, 27,
// and 89 observed login changes, each recorded, zero unknown endpoints.
// Exact membership only: 2.1.293–295 have no proven changes at those versions.
const RECORDED_LOGIN_PROVEN_VERSIONS: &[&str] = &["2.1.300", "2.1.303", "2.1.308", "2.1.310"];

#[derive(Clone)]
pub(super) struct ApprovedOwner {
    slot_id: String,
    account: String,
    org: String,
    email: String,
    owner_since: Option<u64>,
}
impl std::fmt::Debug for ApprovedOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovedOwner { qualified: true }")
    }
}
crate::heap_layout_bound::fields!(ApprovedOwner; slot_id, account, org, email, owner_since);

pub(super) fn approved_owners() -> BTreeMap<crate::claude_status_coverage::HomeKey, ApprovedOwner> {
    let store = ottto_core::FileClaudeConfigSlotSettingsStore::default();
    let (Ok(registry), Ok(approvals)) = (store.load(), store.slot_approvals()) else {
        return BTreeMap::new();
    };
    registry
        .managed_slots
        .iter()
        .chain(&registry.external_slots)
        .filter_map(|slot| {
            let home = Path::new(slot.config_dir.as_deref()?);
            let approval = approvals.get(&slot.slot_id)?;
            let email = crate::agent_status::approved_claude_slot_email(home, &approval.binding)?;
            Some((
                crate::claude_status_coverage::home_key(home),
                ApprovedOwner {
                    slot_id: slot.slot_id.clone(),
                    account: approval.binding.account_identifier_hash.clone(),
                    org: approval.binding.organization_identifier_hash.clone(),
                    email,
                    owner_since: store.slot_owner_since(&slot.slot_id).ok().flatten(),
                },
            ))
        })
        .collect()
}

/// Local-only decision bound to the approved pair and the precise cached
/// prefix. Old entries decode to None, and never request a historical read.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SavedProof {
    account: String,
    org: String,
    checkpoint: Option<String>,
    stable_and_equals_approved_owner: bool,
    first_activity: Option<i64>,
}
crate::heap_layout_bound::fields!(SavedProof; account, org, checkpoint, stable_and_equals_approved_owner, first_activity);
impl SavedProof {
    fn matches(&self, owner: &ApprovedOwner) -> bool {
        self.stable_and_equals_approved_owner
            && self.account == owner.account
            && self.org == owner.org
    }
}

/// Parser-local only. Neither this shape nor ApprovedOwner is durable-coded.
/// A Tail ANDs new observations with a certified prior decision. Unknown
/// prefixes remain unknown until an independently required ordinary Full.
pub(super) struct Proof {
    owner: ApprovedOwner,
    previous: Option<Box<SavedProof>>,
    valid: bool,
    context_seen: bool,
    version_seen: bool,
}
crate::heap_layout_bound::fields!(Proof; owner, previous, valid, context_seen, version_seen);
impl Proof {
    pub(super) fn configure(
        parser: &mut OwnedJsonlParser,
        path: &Path,
        metadata: &ClaudeTitleMetadata,
        index: &ScanIndex,
    ) {
        parser.slot_owner_proof = crate::claude_status_coverage::transcript_home_key(path)
            .and_then(|home| metadata.slot_owners.get(&home))
            .map(|owner| {
                Box::new(Self {
                    owner: owner.clone(),
                    previous: index
                        .files
                        .get(&local_index_key(path))
                        .and_then(|entry| entry.session_slot_owner_proof.clone()),
                    valid: true,
                    context_seen: false,
                    version_seen: false,
                })
            });
    }

    pub(super) fn restore(
        &mut self,
        mode: crate::transcript_acquisition::ReadMode,
        checkpoint: Option<&crate::transcript_acquisition::Checkpoint>,
    ) {
        if matches!(mode, crate::transcript_acquisition::ReadMode::Full(_)) {
            self.valid = true;
            self.context_seen = false;
            self.version_seen = false;
        } else {
            let key = checkpoint.and_then(checkpoint_key);
            let proven = self.previous.as_ref().is_some_and(|old| {
                old.matches(&self.owner) && key.is_some() && old.checkpoint == key
            });
            self.valid = proven;
            self.context_seen = proven;
            self.version_seen = proven;
        }
        self.previous = None;
    }

    pub(super) fn note_line(&mut self, value: &Value) {
        if let Some(version) = value.get("version") {
            self.version_seen = true;
            self.valid &= version
                .as_str()
                .is_some_and(|v| RECORDED_LOGIN_PROVEN_VERSIONS.contains(&v));
        }
        if claude_fork_line_provenance(value) == ClaudeForkLineProvenance::Inherited
            || value.get("entrypoint").and_then(Value::as_str) == Some("claude-desktop")
        {
            self.valid = false;
        }
        let Some(attachment) = value
            .get("attachment")
            .filter(|_| value.get("type").and_then(Value::as_str) == Some("attachment"))
        else {
            return;
        };
        match attachment.get("type").and_then(Value::as_str) {
            Some("session_context") => {
                self.context_seen = true;
                self.valid &= attachment
                    .get("context")
                    .and_then(|v| v.get("userEmail"))
                    .and_then(Value::as_str)
                    .and_then(crate::agent_status::extract_single_email)
                    .is_some_and(|email| email == self.owner.email);
            }
            Some("prompt_snapshot") => {
                if let Some(prompt) = attachment.get("systemPrompt") {
                    self.valid &= !foreign_prompt_slot(prompt, &self.owner.slot_id);
                }
            }
            _ => {}
        }
    }

    /// Wire heap beyond SnapshotItem's already measured inline slot. Hash
    /// clones have exact lengths; normalized RFC3339 text is <=64 bytes.
    pub(super) fn output_heap_bound(&self) -> usize {
        self.owner.account.len() + self.owner.org.len() + 64
    }

    pub(super) fn finish(&self, parser: &OwnedJsonlParser) -> Option<Box<SavedProof>> {
        (self.valid
            && !parser.accumulator.claude_owned_session_id_conflicted
            && self.context_seen
            && self.version_seen
            && parser
                .accumulator
                .claude_org_markers
                .as_deref()
                .is_some_and(|markers| markers.all_orgs_equal(&self.owner.org))
            && sampled_jsonl::loss_free_source_report(
                &parser.reader.report,
                parser.recognized_usage_drop_count,
                parser.accumulator.dropped_usage_record_count,
            ))
        .then(|| {
            Box::new(SavedProof {
                account: self.owner.account.clone(),
                org: self.owner.org.clone(),
                checkpoint: None,
                stable_and_equals_approved_owner: true,
                first_activity: None,
            })
        })
    }
}

/// Prompt snapshots carry strings or structured content blocks. Inspect only
/// this native attachment, never arbitrary user text or tool output.
fn foreign_prompt_slot(prompt: &Value, own: &str) -> bool {
    match prompt {
        Value::String(text) => text.split("claude_slot_").skip(1).any(|suffix| {
            let bytes = suffix.as_bytes();
            bytes.len() > 32
                && bytes[..32].iter().all(u8::is_ascii_hexdigit)
                && matches!(bytes[32], b'/' | b'\\')
                && own.strip_prefix("claude_slot_") != suffix.get(..32)
        }),
        Value::Array(parts) => parts.iter().any(|part| foreign_prompt_slot(part, own)),
        Value::Object(parts) => parts.values().any(|part| foreign_prompt_slot(part, own)),
        _ => false,
    }
}

/// Reuse the existing content-free certificate and JSON digest writer. The
/// audit scheduling fields can change independently of the certified bytes.
fn checkpoint_key(checkpoint: &crate::transcript_acquisition::Checkpoint) -> Option<String> {
    let c = checkpoint.durable_certificate(0)?;
    let digest = serialized_json_digest(
        &(
            checkpoint.scope().0.as_str(),
            c.device,
            c.inode,
            c.length,
            c.modified,
            c.sealed_offset,
            c.sample_len,
            c.head_sha256,
            c.boundary_sha256,
        ),
        b"session_slot_owner:checkpoint:v1\0",
    )?;
    Some(format!("{:x}", digest.finalize()))
}

pub(super) fn seal(
    proof: &mut SavedProof,
    completed: Option<&sampled_jsonl::CompletedNativeAcquisition>,
    items: &[SnapshotItem],
) {
    proof.checkpoint = completed
        .filter(|c| !c.unsealed)
        .and_then(|c| checkpoint_key(&c.checkpoint));
    proof.first_activity = items
        .iter()
        .filter_map(|item| item.source_started_at.as_deref())
        .filter_map(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
        .map(|t| t.unix_timestamp())
        .min();
}

pub(super) fn owner_for(
    path: &Path,
    proof: Option<&SavedProof>,
    metadata: &ClaudeTitleMetadata,
    index: &ScanIndex,
    support_dir: Option<&Path>,
    twins: &std::cell::OnceCell<claude_history_upgrade::ClaudeTwinGroups>,
    require_census: bool,
) -> Option<SessionSlotOwner> {
    if !index.session_slot_owner_enabled
        || claude_subagent_identity(path).is_some()
        || (require_census
            && !index
                .traversal
                .as_ref()
                .is_some_and(codex_frozen_census_valid))
        || metadata.original_identity_census_incomplete
        || metadata.sidecar_census_incomplete
    {
        return None;
    }
    let session = path.file_stem()?.to_str()?;
    if metadata.desktop_sessions.contains(session)
        || metadata
            .session_account_evidence(session)
            .identity_disposition
            != Some("missing")
        || !crate::claude_local_otel::claude_sidecars_absent(support_dir?, session)
    {
        return None;
    }
    // Same complete home census and twin spelling as the money reducer.
    let twins = twins.get()?;
    let own_key = local_index_key(path);
    if twins
        .get(session)
        .is_some_and(|keys| keys.iter().any(|(key, _)| key != &own_key))
    {
        return None;
    }
    let owner = metadata
        .slot_owners
        .get(&crate::claude_status_coverage::transcript_home_key(path)?)?;
    let proof = proof.filter(|proof| proof.matches(owner))?;
    let owner_since = owner
        .owner_since
        .and_then(|seconds| i64::try_from(seconds).ok())
        .filter(|seconds| proof.first_activity.is_some_and(|first| *seconds <= first))
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .map(|text| text.into_boxed_str().into_string());
    Some(SessionSlotOwner {
        provider: "anthropic",
        account_identifier_hash: owner.account.clone(),
        provider_workspace_hash: owner.org.clone(),
        identity_hash_scheme: "provider-sha256:v1",
        basis: if owner_since.is_some() {
            "owner_since"
        } else {
            "recorded_login:v1"
        },
        owner_since,
    })
}

/// Only an actually emitted field extends the ordinary sidecar fingerprint.
/// The caller finalizes this after parsing, so the next pre-open comparison
/// reconstructs the same revision and cannot enter a proof/re-offer loop.
pub(super) fn fingerprint(base: &str, owner: Option<&SessionSlotOwner>) -> String {
    match owner {
        None => base.to_owned(),
        Some(owner) => sha256_hex(&[
            base,
            CONTRACT,
            &serde_json::to_string(owner).expect("wire owner serializes"),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money};
    use crate::transcript_acquisition::Scope;

    /// [money] The own recorded login adds only the approved hashes; moves,
    /// retained twins and a child stay unproven, with cold/Tail totals conserved.
    #[test]
    fn recorded_login_owner_conserves_money_across_tail_and_negative_homes() {
        let (dir, specimen, _, _) = claude_request_account_mixed_fixture(4, false);
        let session = specimen.source_session_id;
        let native: Vec<Value> = fs::read_to_string(dir.join(format!("{session}.jsonl")))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let home = dir.join(format!("claude_slot_{}", "1".repeat(32)));
        let project = home.join("projects/synthetic");
        let other_home = dir.join(format!("claude_slot_{}", "2".repeat(32)));
        let support = dir.join("support");
        fs::create_dir_all(&project).unwrap();
        let account_uuid = "11111111-1111-4111-8111-111111111111";
        let org_uuid = "22222222-2222-4222-8222-222222222222";
        let binding = ottto_core::ClaudeSlotAccountBinding::new(
            &ottto_core::billing_identity_hash("anthropic", "account", account_uuid).unwrap(),
            &ottto_core::billing_identity_hash("anthropic", "organization", org_uuid).unwrap(),
        )
        .unwrap();
        fs::write(home.join(".claude.json"), serde_json::to_vec(&json!({"oauthAccount": {
            "accountUuid":account_uuid, "organizationUuid":org_uuid, "emailAddress":"owner@example.invalid"
        }})).unwrap()).unwrap();
        let email = crate::agent_status::approved_claude_slot_email(&home, &binding).unwrap();
        for changed in [
            ottto_core::ClaudeSlotAccountBinding::new(
                &"a".repeat(64),
                &binding.organization_identifier_hash,
            )
            .unwrap(),
            ottto_core::ClaudeSlotAccountBinding::new(
                &binding.account_identifier_hash,
                &"b".repeat(64),
            )
            .unwrap(),
        ] {
            assert!(crate::agent_status::approved_claude_slot_email(&home, &changed).is_none());
        }
        let owner = ApprovedOwner {
            slot_id: format!("claude_slot_{}", "1".repeat(32)),
            account: binding.account_identifier_hash.clone(),
            org: binding.organization_identifier_hash.clone(),
            email,
            owner_since: None,
        };
        let context = |email: &str| {
            json!({"type":"attachment", "attachment": {
                "type":"session_context", "context":{"userEmail":format!("Logged in as {email}.")}
            }})
        };
        let marker = json!({"type":"attachment", "attachment":{"type":"credential_org", "organizationUuid":org_uuid}});
        let rows = |id: &str, selected: &[Value], moved: bool, with_context: bool| {
            let mut out = Vec::new();
            if with_context {
                out.extend([
                    context("owner@example.invalid"),
                    marker.clone(),
                    json!({"type":"attachment", "attachment": {
                        "type":"prompt_snapshot", "systemPrompt":[format!(
                            "Local instructions in {}/projects/synthetic", owner.slot_id
                        )]
                    }}),
                ]);
            }
            for (at, row) in selected.iter().enumerate() {
                if moved && at == 1 {
                    out.push(context("other@example.invalid"));
                }
                let mut row = row.clone();
                row["sessionId"] = json!(id);
                row["requestId"] = json!(format!("{id}-{}", row["requestId"].as_str().unwrap()));
                row["version"] = json!("2.1.310");
                out.push(row);
            }
            out.into_iter()
                .map(|row| serde_json::to_string(&row).unwrap() + "\n")
                .collect::<String>()
        };
        let path = project.join(format!("{session}.jsonl"));
        fs::write(&path, rows(&session, &native[..2], false, true)).unwrap();
        let run =
            |mut index: ScanIndex, cache: Option<Arc<sampled_scan::SharedCache>>, enabled: bool| {
                // Inject the synthetic qualified approval after construction, so
                // this test never reads the host registry or provider login.
                index.session_slot_owner_enabled = false;
                let mut scan = OwnedSourceScan::new_with_identity_capture(
                    SnapshotSource::ClaudeCode,
                    std::slice::from_ref(&project),
                    index,
                    "2026-08-02T07:10:00Z",
                    BACKFILL_WINDOW_DAYS,
                    100,
                    false,
                    Some(&support),
                    &[],
                    false,
                    true,
                );
                scan.index.session_slot_owner_enabled = enabled;
                if enabled {
                    scan.claude_title_metadata.slot_owners.insert(
                        crate::claude_status_coverage::home_key(&home),
                        owner.clone(),
                    );
                }
                if let Some(cache) = cache {
                    scan = scan.with_sampled_acquisition(cache, Scope("slot-owner-fixture".into()));
                }
                for _ in 0..10_000 {
                    let modes = scan.sampling.as_ref().map_or((0, 0, 0), |context| {
                        (
                            context.full_files,
                            context.tail_files,
                            context.unchanged_files,
                        )
                    });
                    match scan.step(None) {
                        OwnedSourceScanStep::Pending(next) => scan = next,
                        OwnedSourceScanStep::Complete { index, scan, .. } => {
                            return (index, scan, modes)
                        }
                    }
                }
                panic!("small fixture did not complete");
            };
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (prefix_index, prefix, _) = run(ScanIndex::default(), Some(cache.clone()), true);
        assert_eq!(prefix.snapshots.len(), 1);
        assert!(prefix.snapshots[0].session_slot_owner.is_some());
        // Persisted proof survives the ordinary index round trip. The cache
        // separately supplies and validates the exact prefix certificate.
        let mut warm_index: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&prefix_index).unwrap()).unwrap();
        fs::write(&path, rows(&session, &native, false, true)).unwrap();
        let moved = "33333333-3333-4333-8333-333333333333";
        let twin = "44444444-4444-4444-8444-444444444444";
        fs::write(
            project.join(format!("{moved}.jsonl")),
            rows(moved, &native, true, true),
        )
        .unwrap();
        let foreign = "55555555-5555-4555-8555-555555555555";
        fs::write(
            project.join(format!("{foreign}.jsonl")),
            rows(foreign, &native, false, true)
                + &serde_json::to_string(&json!({"type":"attachment", "attachment": {
                    "type":"prompt_snapshot", "systemPrompt":[format!(
                        "Local instructions in claude_slot_{}/projects/synthetic", "2".repeat(32)
                    )]
                }}))
                .unwrap()
                + "\n",
        )
        .unwrap();
        fs::write(
            project.join(format!("{twin}.jsonl")),
            rows(twin, &native, false, true),
        )
        .unwrap();
        let other = other_home.join(format!("projects/synthetic/{twin}.jsonl"));
        fs::create_dir_all(other.parent().unwrap()).unwrap();
        fs::write(&other, rows(twin, &native, false, true)).unwrap();
        let twin_entry: ScanIndexEntry = serde_json::from_value(json!({
            "size_bytes":fs::metadata(&other).unwrap().len(), "modified_unix_seconds":0,
            "source_file_fingerprint":"retained-other-home"
        }))
        .unwrap();
        warm_index
            .files
            .insert(local_index_key(&other), twin_entry.clone());
        let child = project
            .join(&session)
            .join("subagents/agent-a4d1585d310070d0f.jsonl");
        fs::create_dir_all(child.parent().unwrap()).unwrap();
        let mut child_row = native[0].clone();
        child_row["agentId"] = json!("a4d1585d310070d0f");
        child_row["isSidechain"] = json!(true);
        child_row["requestId"] = json!("child-own-request");
        fs::write(&child, rows(&session, &[child_row], false, false)).unwrap();
        let (warm_index, warm, modes) = run(warm_index, Some(cache.clone()), true);
        if crate::heap_layout_bound::layout_supported() {
            assert!(modes.1 > 0, "the eligible prefix must continue by Tail");
        }
        let (_, quiet, _) = run(warm_index.clone(), Some(cache), true);
        assert!(
            quiet.snapshots.is_empty(),
            "an unchanged owner is offered once"
        );
        let mut fresh = ScanIndex::default();
        fresh.files.insert(local_index_key(&other), twin_entry);
        let (cold_index, cold, _) = run(fresh.clone(), None, true);
        let (_, off, _) = run(fresh, None, false);
        let item = warm
            .snapshots
            .iter()
            .find(|item| item.source_session_id == session)
            .unwrap();
        let wire = serde_json::to_value(item).unwrap();
        assert_eq!(
            wire["session_slot_owner"],
            json!({
                "provider":"anthropic", "account_identifier_hash":binding.account_identifier_hash,
                "provider_workspace_hash":binding.organization_identifier_hash,
                "identity_hash_scheme":"provider-sha256:v1", "basis":"recorded_login:v1"
            })
        );
        assert!(warm
            .snapshots
            .iter()
            .filter(|item| item.source_session_id != session)
            .all(|item| item.session_slot_owner.is_none()));
        assert!(warm
            .snapshots
            .iter()
            .any(|item| item.source_session_id == moved));
        assert!(warm
            .snapshots
            .iter()
            .any(|item| item.source_session_id == twin));
        assert!(warm
            .snapshots
            .iter()
            .any(|item| item.source_session_id == foreign));
        assert!(warm
            .snapshots
            .iter()
            .any(|item| item.source_session_id.contains("_agent-")));
        money_oracle::assert_equivalent(
            &scan_money(SnapshotSource::ClaudeCode, &cold_index, &cold),
            &scan_money(SnapshotSource::ClaudeCode, &warm_index, &warm),
        );
        let totals = |scan: &SourceScanResult| {
            scan.snapshots.iter().fold([0u64; 8], |mut sums, item| {
                for (sum, value) in sums.iter_mut().zip([
                    item.request_count,
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.cache_creation_5m_tokens,
                    item.cache_creation_1h_tokens,
                    item.reasoning_output_tokens,
                    item.unattributed_total_tokens,
                ]) {
                    *sum += value;
                }
                sums
            })
        };
        assert_eq!(totals(&warm), totals(&off));
        assert!(totals(&warm)[0] > 0);
        assert!(off
            .snapshots
            .iter()
            .all(|item| item.session_slot_owner.is_none()));
        // All fields outside the new evidence/fingerprint remain identical.
        let without_owner = |scan: &SourceScanResult| {
            let mut bodies: Vec<Value> = scan
                .snapshots
                .iter()
                .map(|item| {
                    let mut body = serde_json::to_value(item).unwrap();
                    body.as_object_mut().unwrap().remove("session_slot_owner");
                    body.as_object_mut()
                        .unwrap()
                        .remove("source_file_fingerprint");
                    body
                })
                .collect();
            bodies.sort_by_key(|item| item["source_session_id"].to_string());
            bodies
        };
        assert_eq!(without_owner(&cold), without_owner(&off));
        fs::remove_dir_all(dir).unwrap();
    }
}
