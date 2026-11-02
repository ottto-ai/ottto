//! A setting or capability flip is delivery debt, never a transcript read.
//! Synthetic inputs.
use super::*;
use sampled_scan::transition_fixture::{money_oracle::assert_equivalent, scan_money};
use serde_json::Value;

const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];
const RETAINED: [&str; 9] = [
    "session_display_name",
    "session_display_name_source",
    "workspace_display_label",
    "workspace_label_source",
    "repository_label",
    "repository_label_source",
    "session_artifacts",
    "attribution_facts",
    "activity_summary",
];

/// Every input of the delivery context: the five settings, the attribution
/// key, the cache capability and the copy-unproven capability.
#[derive(Clone, Copy)]
struct Mode {
    policy: SnapshotUploadPolicy,
    key: u8,
    cache: bool,
    copy: bool,
}
type Flip = (&'static str, fn(&mut Mode));
const FLIPS: [Flip; 8] = [
    ("titles", |m| flip(&mut m.policy.session_titles_enabled)),
    ("workspace", |m| {
        flip(&mut m.policy.workspace_labels_enabled)
    }),
    ("links", |m| flip(&mut m.policy.session_artifacts_enabled)),
    ("attribution", |m| {
        flip(&mut m.policy.session_attribution_enabled)
    }),
    ("labels", |m| {
        flip(&mut m.policy.session_attribution_labels_enabled)
    }),
    ("key", |m| m.key ^= 1),
    ("cache", |m| flip(&mut m.cache)),
    ("copy", |m| flip(&mut m.copy)),
];
fn flip(value: &mut bool) {
    *value = !*value;
}

fn all(value: bool) -> SnapshotUploadPolicy {
    SnapshotUploadPolicy {
        session_titles_enabled: value,
        workspace_labels_enabled: value,
        session_artifacts_enabled: value,
        session_attribution_enabled: value,
        session_attribution_labels_enabled: value,
    }
}
fn mode(value: bool) -> Mode {
    Mode {
        policy: all(value),
        key: 0,
        cache: value,
        copy: value,
    }
}
fn flipped(mut mode: Mode, flip: &Flip) -> Mode {
    (flip.1)(&mut mode);
    mode
}
/// The attribution context for key epoch `key`.
fn attribution(
    source: SnapshotSource,
    root: &Path,
    key: u8,
) -> crate::session_attribution::SessionAttributionContext {
    use base64::Engine;
    crate::session_attribution::SessionAttributionContext::from_activity_hint(
        source,
        root,
        true,
        Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13 + key; 32])),
        Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .unwrap()
}

struct Walked {
    scan: SourceScanResult,
    retained: Vec<Value>,
    modes: (usize, usize, usize),
    bytes: u64,
}

impl Fixture {
    fn flip(&mut self, policy: SnapshotUploadPolicy) {
        self.flip_to(Mode {
            policy,
            ..mode(false)
        });
    }
    /// The service prepare's activation under `mode`: copy-unproven is a
    /// Claude capability, the key namespace exists only with attribution on.
    fn flip_to(&mut self, mode: Mode) {
        let namespace = mode
            .policy
            .session_attribution_enabled
            .then(|| attribution(self.source, &self.root, mode.key).checkpoint_namespace());
        self.uploader.activate_like_prepare(
            self.source,
            &mut self.index,
            mode.policy,
            namespace.as_deref(),
            mode.cache,
            mode.copy && self.source == SnapshotSource::ClaudeCode,
        );
    }
    fn attribution_for(
        &self,
        mode: Mode,
    ) -> Option<crate::session_attribution::SessionAttributionContext> {
        mode.policy
            .session_attribution_enabled
            .then(|| attribution(self.source, &self.root, mode.key))
    }
    /// A walk under `policy`, as the service runs it: the scan first, then the
    /// upload filter, then finalization. `retained` is what the scan kept.
    fn flip_walk(
        &mut self,
        policy: SnapshotUploadPolicy,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Walked {
        let mut scan = OwnedSourceScan::new(
            self.source,
            std::slice::from_ref(&self.root),
            std::mem::take(&mut self.index),
            "2026-10-29T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            10,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            self.cache.clone(),
            crate::transcript_acquisition::Scope("upload-context-fixture".into()),
        );
        let (mut modes, mut bytes) = ((0, 0, 0), 0);
        loop {
            if let Some(sampling) = scan.sampling.as_ref() {
                modes = (
                    sampling.full_files,
                    sampling.tail_files,
                    sampling.unchanged_files,
                );
                bytes = sampling.native_bytes;
            }
            match scan.step(attribution) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    index, mut scan, ..
                } => {
                    self.index = index;
                    scan.census_complete = false;
                    let retained = scan
                        .snapshots
                        .iter()
                        .map(|item| {
                            let body = serde_json::to_value(item).unwrap();
                            let fields = RETAINED.map(|field| (field, body[field].clone()));
                            json!(BTreeMap::from(fields))
                        })
                        .collect();
                    apply_upload_policy(self.source, &mut scan.snapshots, policy);
                    finalize_scan_after_policy(self.source, &mut scan, &mut self.index);
                    return Walked {
                        scan,
                        retained,
                        modes,
                        bytes,
                    };
                }
            }
        }
    }
    fn send_all(&mut self, committed: &ScanIndex, scan: &SourceScanResult) {
        let context = self
            .index
            .active_upload_context_fingerprint
            .clone()
            .unwrap();
        self.uploader
            .activate(self.source, context, &mut self.index);
        self.uploader
            .send(self.source, &mut self.index, committed, &scan.snapshots)
            .unwrap();
    }
    fn append(&self, lines: &[Value]) {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }
    fn read_owed(&self) -> bool {
        self.index.file_context_read_owed(&self.key())
    }
    fn debt(&self) -> bool {
        self.index
            .file_upload_context_requires_adoption(&self.key())
    }
    /// A restart: the index reloads, RAM checkpoints and the cache are gone,
    /// the upload ledger reloads, and the prepare activates `mode` again.
    fn restart(&mut self, mode: Mode) {
        let path = self._scratch.join("restart-index.json");
        self.index.save(&path).unwrap();
        self.index = ScanIndex::load(&path).unwrap();
        self.cache = Arc::default();
        self.flip_to(mode);
        let context = self
            .index
            .active_upload_context_fingerprint
            .clone()
            .unwrap();
        self.uploader.restart(self.source, &context);
    }
}

fn link(n: u32) -> Value {
    json!({"timestamp":format!("2026-10-29T10:0{n}:30Z"),"sessionId":SESSION,"message":{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":format!("Opened https://github.com/ottto-ai/repo/pull/{n}")}]}]}})
}
/// Title, workspace and link material where the source's format carries them.
fn material(source: SnapshotSource) -> Vec<Value> {
    match source {
        SnapshotSource::ClaudeCode => vec![
            json!({"timestamp":"2026-10-29T10:00:00Z","sessionId":SESSION,"summary":"Synthetic title","cwd":"/synthetic/repo","gitBranch":"main"}),
            link(0),
        ],
        _ => Vec::new(),
    }
}
fn growth(source: SnapshotSource) -> Vec<Value> {
    match source {
        SnapshotSource::Codex => vec![
            json!({"timestamp":"2026-10-29T10:01:00Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":30,"output_tokens":9}}}}),
        ],
        SnapshotSource::Pi => vec![
            json!({"type":"message_end","message":{"responseId":"synthetic-response-2","model":"gpt-5.4","timestamp":"1793268061000","usage":{"input":20,"output":6}}}),
        ],
        _ => vec![
            json!({"type":"assistant","sessionId":SESSION,"timestamp":"2026-10-29T10:01:00Z","requestId":"synthetic-request-2","message":{"id":"synthetic-message-2","model":"claude-sonnet-4-6","usage":{"input_tokens":20,"output_tokens":6}}}),
            link(1),
        ],
    }
}
/// A fixture whose file was uploaded and exactly acknowledged under `mode`.
fn settled(source: SnapshotSource, mode: Mode) -> Fixture {
    let mut f = Fixture::new(source);
    f.append(&material(source));
    f.flip_to(mode);
    assert_eq!(f.adopt().files, 1);
    assert!(!f.debt());
    f
}
fn settled_policy(source: SnapshotSource, policy: SnapshotUploadPolicy) -> Fixture {
    settled(
        source,
        Mode {
            policy,
            ..mode(false)
        },
    )
}

/// [money] T1, the gate: for every source and every setting or capability
/// bit in both directions, a Tail under B after a parse under A equals a Full
/// under B: money, placement, everything the scan retains for titles, links
/// and attribution, and the bodies POSTed. Attribution is under the key at
/// send: the whole session re-keys, as a cold Full under B.
#[test]
fn tail_under_flipped_mode_equals_full_for_every_bit() {
    for source in SOURCES {
        for bit in &FLIPS {
            for start in [false, true] {
                let before = mode(start);
                let after = flipped(before, bit);
                let label = format!("{source:?}/{}/{start}", bit.0);
                let mut f = Fixture::new(source);
                f.append(&material(source));
                f.flip_to(before);
                let committed = f.index.clone();
                let parsed = f.flip_walk(before.policy, f.attribution_for(before).as_ref());
                f.send_all(&committed, &parsed.scan);
                assert!(!f.debt(), "{label}: parsed and acknowledged under A");
                f.flip_to(after);
                f.append(&growth(source));
                let committed = f.index.clone();
                let tail = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
                assert_eq!(tail.modes, (0, 1, 0), "{label}");
                assert!(tail.bytes > 0, "{label}: the append is read");
                let tail_money = scan_money(source, &f.index, &tail.scan);
                let posted = f.uploader.posts.len();
                f.send_all(&committed, &tail.scan);
                let tail_posts = f.uploader.posts[posted..].concat();
                assert!(!f.debt(), "{label}: the send pays the debt");

                f.index = ScanIndex::default();
                f.cache = Arc::default();
                f.uploader =
                    crate::snapshot_sync::upload_context_receipt_tests::Uploader::new(source);
                f.flip_to(after);
                let committed = f.index.clone();
                let cold = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
                assert_eq!(cold.modes.0, 1, "{label}: the control is a Full");
                assert_eq!(cold.retained, tail.retained, "{label}");
                let cold_money = scan_money(source, &f.index, &cold.scan);
                assert_equivalent(&cold_money, &tail_money);
                f.send_all(&committed, &cold.scan);
                let cold_posts = f.uploader.posts.concat();
                assert!(!cold_posts.is_empty(), "{label}: the control posts");
                assert_eq!(tail_posts, cold_posts, "{label}: POSTed bodies");

                if source == SnapshotSource::ClaudeCode {
                    let kept = cold.retained[0].to_string();
                    for material in ["Synthetic title", "pull/0", "pull/1"] {
                        assert!(kept.contains(material), "{label}: {material} retained");
                    }
                }
                let mut tampered = tail.scan;
                tampered.snapshots[0].input_tokens += 1;
                let tampered = scan_money(source, &f.index, &tampered);
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        assert_equivalent(&cold_money, &tampered)
                    }))
                    .is_err(),
                    "{label}: positive control"
                );
            }
        }
    }
}

/// [behaviour] T2: every bit, every source, unchanged file: zero bytes read
/// and nothing POSTed, also after a restart. A settings or key change is owed
/// delivery, paid on the next ordinary read; a copy-mode change of an
/// unaffected file is already proven by its mode-free receipt.
#[test]
fn flip_reads_and_sends_nothing_on_unchanged_files() {
    for source in SOURCES {
        for bit in &FLIPS {
            for start in [false, true] {
                let label = format!("{source:?}/{}/{start}", bit.0);
                let before = mode(start);
                let after = flipped(before, bit);
                let mut f = settled(source, before);
                let context = f.index.active_upload_context_fingerprint.clone();
                f.flip_to(after);
                let changed = f.index.active_upload_context_fingerprint != context;
                if changed && bit.0 != "copy" {
                    assert!(f.debt(), "{label}: the flip owes delivery");
                }
                assert!(!f.read_owed(), "{label}");
                f.assert_quiet();
                f.restart(after);
                assert!(!f.read_owed(), "{label}: after a restart");
                f.assert_quiet();
            }
        }
    }
}

/// [money] T6: the operator's scoped copy-prefix re-read still owes its read
/// when only the copy mode moved; the broadened gate does not swallow it.
#[test]
fn copy_prefix_reread_mode_debt_still_selects() {
    let mut f = settled(SnapshotSource::ClaudeCode, mode(false));
    f.flip_to(Mode {
        copy: true,
        ..mode(false)
    });
    assert!(!f.read_owed(), "an unaffected file");
    let key = f.key();
    let marks = f
        .index
        .claude_money_birth_store
        .money_marks(claude_money_birth_store::location_key(&key));
    f.index
        .claude_money_birth_store
        .set_money_marks(&key, marks | claude_copy_prefix_reread::REOWED);
    assert!(f.read_owed(), "a requested re-read under another mode");
}

/// [behaviour] T4: A -> B -> A with no upload under B is simply current again.
#[test]
fn flip_and_back_without_upload_is_current() {
    let mut f = settled_policy(SnapshotSource::Codex, all(false));
    f.flip(flipped(mode(false), &FLIPS[0]).policy);
    f.assert_quiet();
    f.flip(all(false));
    assert!(!f.debt());
    f.assert_quiet();
}

/// [behaviour] T4: an ACK under B is not reused after going back to A: the next
/// acquisition resends under A; until then the server keeps B's form.
#[test]
fn flip_back_after_acknowledged_upload_resends_on_next_read() {
    let mut f = settled_policy(SnapshotSource::Codex, all(false));
    let b = flipped(mode(false), &FLIPS[0]).policy;
    f.flip(b);
    f.append(&growth(f.source));
    let committed = f.index.clone();
    let walked = f.flip_walk(b, None);
    f.send_all(&committed, &walked.scan);
    assert!(!f.debt());
    f.flip(all(false));
    assert!(f.debt() && !f.read_owed());
    f.assert_quiet();
    let posts = f.uploader.posts.len();
    f.append(&[json!({"timestamp":"2026-10-29T10:02:00Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":40,"output_tokens":9}}}})]);
    let committed = f.index.clone();
    let walked = f.flip_walk(all(false), None);
    assert_eq!(walked.modes, (0, 1, 0));
    f.send_all(&committed, &walked.scan);
    assert_eq!(f.uploader.posts.len(), posts + 1);
    assert!(!f.debt());
}

/// [behaviour] T4: a page partly acknowledged under B is checkpointed, then the
/// pass fails and rolls back to that checkpoint. Back under A the file still
/// holds A's receipt, but the entities ACKed under B make it select, and the
/// read resends exactly those.
#[test]
fn partial_ack_under_flip_checkpoint_rollback_still_selects() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.flip(all(false));
    let a = f.index.active_upload_context_fingerprint.clone().unwrap();
    let empty = f.index.clone();
    let items = uploader_group(&mut f, 51);
    f.uploader.activate(f.source, a.clone(), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &empty, &items)
            .unwrap()
            .0,
        1
    );
    assert!(!f.debt());
    f.flip(flipped(mode(false), &FLIPS[0]).policy);
    assert!(f.debt() && !f.read_owed());
    let committed = f.index.clone();
    let b = f.index.active_upload_context_fingerprint.clone().unwrap();
    f.uploader.activate(f.source, b.clone(), &mut f.index);
    f.uploader.fail_after = Some(f.uploader.posts.len() + 1);
    assert!(f
        .uploader
        .send(f.source, &mut f.index, &committed, &items)
        .is_err());
    let fingerprints = |posts: &[Vec<Value>]| {
        posts
            .iter()
            .flatten()
            .map(|v| v["snapshot_fingerprint"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>()
    };
    let acked = fingerprints(std::slice::from_ref(f.uploader.posts.last().unwrap()));
    assert!(!acked.is_empty() && acked.len() < items.len());
    // The checkpoint commits the page's ACKs; the failed pass rolls back to it.
    f.index = committed;
    f.uploader.checkpoint_stamps(&mut f.index);
    f.uploader.restart(f.source, &b);
    f.uploader.fail_after = None;
    f.flip(all(false));
    assert!(
        f.debt(),
        "A's receipt no longer proves what the server holds"
    );
    assert!(f.read_owed());
    let committed = f.index.clone();
    let before = f.uploader.posts.len();
    f.uploader.activate(f.source, a, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &items)
        .unwrap();
    assert_eq!(fingerprints(&f.uploader.posts[before..]), acked);
    assert!(!f.debt());
}

/// [behaviour] T4: one entity shared by two files, through A -> B -> A. The
/// alias read under B earns B; the untouched file keeps A's receipt, which is
/// no current proof of the shared entity once back under A.
#[test]
fn shared_entity_acked_under_flip_is_no_proof_for_the_untouched_alias() {
    let mut f = Fixture::new(SnapshotSource::Pi);
    f.flip(all(false));
    let a = f.index.active_upload_context_fingerprint.clone().unwrap();
    let empty = f.index.clone();
    let (mut scan, _) = f.walk(false);
    let mut shared = scan.snapshots[0].clone();
    shared.source_session_id = "synthetic-shared-session".into();
    scan.snapshots.push(shared.clone());
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader.activate(f.source, a.clone(), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &empty, &scan.snapshots)
        .unwrap();
    let untouched = f.key();
    let shared_entity = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == shared.source_session_id)
        .unwrap()
        .snapshot_fingerprint
        .clone();

    let alias_session = "019fa111-2222-7333-8444-777777777777";
    let alias_path = f.root.join(format!("{alias_session}.jsonl"));
    fs::write(
        &alias_path,
        [
            json!({"type":"session","id":alias_session,"timestamp":"2026-10-29T10:00:00Z"}),
            json!({"type":"message_end","message":{"responseId":"synthetic-alias","model":"gpt-5.4","timestamp":"1793268001000","usage":{"input":7,"output":3}}}),
        ]
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>(),
    )
    .unwrap();
    let alias = local_index_key(&alias_path);
    let committed = f.index.clone();
    let (mut scan, _) = f.walk(false);
    assert!(
        scan.snapshots
            .iter()
            .all(|item| item.source_session_id != SESSION),
        "only the new alias is read"
    );
    let alias_file = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == alias_session)
        .unwrap()
        .source_file_fingerprint
        .clone();
    scan.snapshots.push(SnapshotItem {
        source_file_fingerprint: alias_file,
        ..shared
    });
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    let alias_items = scan.snapshots;
    f.uploader.activate(f.source, a, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &alias_items)
        .unwrap();
    for key in [&untouched, &alias] {
        assert!(f.index.file_snapshot_fingerprints[key].contains(&shared_entity));
        assert!(!f.index.file_upload_context_requires_adoption(key));
    }

    // Under B the alias is read and acknowledged; the untouched file is not.
    f.flip(flipped(mode(false), &FLIPS[0]).policy);
    assert!(!f.index.file_context_read_owed(&untouched));
    let committed = f.index.clone();
    let b = f.index.active_upload_context_fingerprint.clone().unwrap();
    f.uploader.activate(f.source, b, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &alias_items)
        .unwrap();
    assert!(!f.index.file_upload_context_requires_adoption(&alias));
    assert!(
        f.index.file_context_read_owed(&untouched),
        "the shared entity was sent under B"
    );

    f.flip(all(false));
    assert!(
        !f.index.file_context_read_owed(&alias),
        "the alias owes delivery only"
    );
    assert!(
        f.index.file_upload_context_requires_adoption(&untouched)
            && f.index.file_context_read_owed(&untouched),
        "A's receipt is no current proof of the entity acknowledged under B"
    );
}

/// [behaviour] T5: values persisted by the previous binary. A traversal and
/// carry origin bound to the active delivery context and replay generation
/// are rewritten to the new form; one bound to another context keeps today's
/// mismatch, which starts the walk. Tier receipts and archive contexts are
/// never compared, so neither reads nor holds. Nothing is read or sent.
#[test]
fn upgrade_from_delivery_bound_state_reads_and_holds_nothing() {
    for source in SOURCES {
        let mut f = Fixture::new(source);
        f.flip(all(false));
        let delivery = f.index.active_upload_context_fingerprint.clone().unwrap();
        // The previous binary wrote every value under the delivery context.
        assert_eq!(f.adopt().files, 1);
        for (name, context) in [
            ("synthetic-archive", delivery.clone()),
            ("other-archive", "another-delivery-context".to_owned()),
        ] {
            f.index.archives.insert(
                name.into(),
                codex_compressed_input::ArchiveEvidence {
                    context: Some(context),
                    owner: None,
                    stamp: None,
                    disposition: codex_compressed_input::ArchiveDisposition::Acquired,
                    work: None,
                },
            );
        }
        let tier_receipt = || {
            serde_json::from_value::<codex_file_join::AppliedTierReceipt>(json!({
                "version": 1, "derivation": "synthetic", "scope": "another-delivery-context",
                "records": 1, "prefix_digest": "synthetic", "tiers": {}
            }))
            .unwrap()
        };
        let key = f.key();
        let entry = f.index.files.get_mut(&key).unwrap();
        entry.codex_captured_tier_receipt = Some(tier_receipt());
        entry.codex_applied_tier_receipt = Some(tier_receipt());
        let roots = [f.root.clone()];
        let legacy = |context: &str| {
            scan_traversal_context_fingerprint_with(
                source,
                &roots,
                Some([
                    Some(context),
                    f.index.historical_replay_generation.as_deref(),
                ]),
                BACKFILL_WINDOW_DAYS,
            )
        };
        let current = scan_traversal_context_fingerprint(source, &roots, BACKFILL_WINDOW_DAYS);
        for (stored, adopted) in [(legacy(&delivery), true), (legacy("another"), false)] {
            let mut traversal = claude_family_census_shadow_tests::traversal();
            traversal.context_fingerprint = stored.clone();
            f.index.traversal = Some(traversal);
            f.index.claude_stale_family_carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
                context_fingerprint: stored.clone(),
                process: 0,
                full_rearm_window: false,
                admission: None,
            });
            adopt_legacy_traversal_fingerprint(source, &roots, &mut f.index, BACKFILL_WINDOW_DAYS);
            let expected = if adopted { &current } else { &stored };
            assert_eq!(
                &f.index.traversal.as_ref().unwrap().context_fingerprint,
                expected,
                "{source:?}/{adopted}"
            );
            assert_eq!(
                &f.index
                    .claude_stale_family_carry
                    .origin
                    .as_ref()
                    .unwrap()
                    .context_fingerprint,
                expected,
                "{source:?}/{adopted}"
            );
        }
        f.index.traversal = None;
        f.index.claude_stale_family_carry.origin = None;

        f.flip(all(false));
        for name in ["synthetic-archive", "other-archive"] {
            assert!(
                matches!(
                    f.index.archives[name].disposition,
                    codex_compressed_input::ArchiveDisposition::Acquired
                ),
                "{source:?}/{name}: no correction is held"
            );
        }
        f.index.archives.clear();
        let entry = f.index.files.get_mut(&key).unwrap();
        for receipt in [
            entry.codex_captured_tier_receipt.take(),
            entry.codex_applied_tier_receipt.take(),
        ] {
            assert_eq!(receipt, Some(tier_receipt()), "{source:?}: untouched");
        }
        assert!(!f.read_owed(), "{source:?}");
        f.assert_quiet();
    }
}

/// [money] T7: context-only debt leaves a member independently accepted for
/// every flip; an entity sent since under another context does not.
#[test]
fn context_only_debt_keeps_consumers_current() {
    for bit in &FLIPS {
        let mut f = settled(SnapshotSource::ClaudeCode, mode(false));
        let key = f.key();
        let accepted = |f: &Fixture| {
            claude_stale_member_independently_accepted(&f.index, &key, &f.index.files[&key])
        };
        assert!(accepted(&f), "{}: positive control, exact ACK", bit.0);
        f.flip_to(flipped(mode(false), bit));
        assert!(accepted(&f), "{}", bit.0);
        for stamp in f.index.upload_context_proof.entity_stamps.values_mut() {
            stamp.context_fingerprint = "f".repeat(64);
        }
        assert!(!accepted(&f), "{}: sent since under another context", bit.0);
    }
}

/// [behaviour] T9: links are collected whatever the toggle says, and the toggle
/// decides the wire.
#[test]
fn links_are_scraped_with_links_off_and_absent_on_the_wire() {
    let off = all(false);
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.append(&material(f.source));
    f.flip(off);
    let walked = f.flip_walk(off, None);
    assert!(walked.retained[0].to_string().contains("pull/0"));
    assert!(walked.scan.snapshots[0].session_artifacts.is_empty());
    let wire = serde_json::to_string(&walked.scan.snapshots).unwrap();
    assert!(!wire.contains("pull/0"));

    let on = flipped(
        Mode {
            policy: off,
            ..mode(false)
        },
        &FLIPS[2],
    )
    .policy;
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.append(&material(f.source));
    f.flip(on);
    let walked = f.flip_walk(on, None);
    assert!(serde_json::to_string(&walked.scan.snapshots)
        .unwrap()
        .contains("pull/0"));
}

/// [behaviour] T9: the server's limit applies at upload; nothing is dropped
/// locally and the item is still sent.
#[test]
fn over_limit_link_is_dropped_only_at_upload() {
    let long = format!("https://example.com/{}", "a".repeat(600));
    let mut item = tests::sample_session_artifact_item();
    item.session_artifacts.push(SessionArtifact {
        kind: "pull_request".into(),
        value: long,
    });
    let before = item.snapshot_fingerprint.clone();
    let mut items = vec![item];
    apply_upload_policy(SnapshotSource::ClaudeCode, &mut items, all(true));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].session_artifacts.len(), 1);
    assert!(items[0].session_artifacts[0].value.len() <= 512);
    assert_eq!(items[0].snapshot_fingerprint, before, "names the sent body");
}
