//! A setting or capability flip is delivery debt, never a transcript read.
//! Synthetic inputs.
use super::*;
use crate::snapshots::privacy_flip_modes::{all, link, Flip, Mode, FLIPS};
use serde_json::Value;

#[path = "privacy_flip_tail_tests.rs"]
mod tail_rows;

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
    /// A walk under `policy`, as the service runs it: the scan first, then the
    /// upload filter, then finalization. `retained` is what the scan kept.
    fn flip_walk(
        &mut self,
        policy: SnapshotUploadPolicy,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Walked {
        // A source with a Tail codec continues from its state database route.
        let index = crate::snapshots::e2_pipeline_scan_fixture::route_for_test(
            self.source,
            Some(self.cache.as_ref()),
            std::mem::take(&mut self.index),
        );
        let mut scan = OwnedSourceScan::new(
            self.source,
            std::slice::from_ref(&self.root),
            index,
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

/// Title, workspace and link material where the source's format carries them.
fn material(source: SnapshotSource) -> Vec<Value> {
    match source {
        SnapshotSource::ClaudeCode => vec![
            json!({"timestamp":"2026-10-29T10:00:00Z","sessionId":SESSION,"summary":"Synthetic title","cwd":"/synthetic/repo","gitBranch":"main"}),
            link(SESSION, "2026-10-29T10:00:30Z", 0),
        ],
        _ => Vec::new(),
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

/// [money] T4: one entity shared by two files. A read of the untouched file
/// depends on the body delivered for it, not on the context: the same body
/// acknowledged through the alias under B selects nothing in A -> B -> A, and
/// other additive evidence, which keeps the entity's hash, selects it at the
/// next flip.
#[test]
fn shared_entity_body_not_context_decides_the_untouched_alias() {
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
    f.uploader.activate(f.source, a.clone(), &mut f.index);
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
        !f.index.file_context_read_owed(&untouched),
        "the shared entity was sent under B with the same body"
    );

    f.flip(all(false));
    assert!(
        !f.index.file_context_read_owed(&alias),
        "the alias owes delivery only"
    );
    assert!(
        f.index.file_upload_context_requires_adoption(&untouched)
            && !f.index.file_context_read_owed(&untouched),
        "B's stamp owes delivery, and the body it proves is the delivered one"
    );

    // Under A again, the alias delivers additive evidence that keeps the
    // entity's hash. The untouched file's receipt describes another body.
    let mut grown = alias_items.clone();
    let carrier = grown
        .iter_mut()
        .find(|item| item.snapshot_fingerprint == shared_entity)
        .unwrap();
    carrier.tool_usage_truncated = true;
    let witness = snapshot_upload_body_witness(carrier);
    let before = f.index.upload_context_proof.entity_stamps[&shared_entity]
        .body_witness
        .clone();
    assert_ne!(before, witness, "the evidence moves the body witness");
    let committed = f.index.clone();
    f.uploader.activate(f.source, a, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &grown)
        .unwrap();
    assert_eq!(
        f.index.upload_context_proof.entity_stamps[&shared_entity].body_witness,
        witness
    );
    f.flip(flipped(mode(false), &FLIPS[0]).policy);
    assert!(
        f.index.file_context_read_owed(&untouched),
        "the same flip that was quiet above selects: the delivered body moved"
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
/// every flip, under whichever context its entities were sent; an entity sent
/// since with another body does not. A file still under its own base has no
/// context-only debt: that is the scoped copy-prefix read.
#[test]
fn context_only_debt_keeps_consumers_current() {
    for bit in &FLIPS {
        let mut f = settled(SnapshotSource::ClaudeCode, mode(false));
        let key = f.key();
        let accepted = |f: &Fixture| {
            claude_stale_member_independently_accepted(&f.index, &key, &f.index.files[&key])
        };
        assert!(accepted(&f), "{}: positive control, exact ACK", bit.0);
        let base = f.index.copy_prefix_base_upload_context.clone();
        f.flip_to(flipped(mode(false), bit));
        assert!(accepted(&f), "{}", bit.0);
        let base_moved = f.index.copy_prefix_base_upload_context != base;
        for stamp in f.index.upload_context_proof.entity_stamps.values_mut() {
            stamp.context_fingerprint = "f".repeat(64);
        }
        assert_eq!(accepted(&f), base_moved, "{}: another context", bit.0);
        for stamp in f.index.upload_context_proof.entity_stamps.values_mut() {
            stamp.body_witness = "f".repeat(64);
        }
        assert!(!accepted(&f), "{}: sent since with another body", bit.0);
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

/// [behaviour] T9: the server's limit, 512 characters, applies at upload;
/// nothing is dropped locally and the item is still sent.
#[test]
fn over_limit_link_is_dropped_only_at_upload() {
    let long = format!("https://example.com/{}", "a".repeat(600));
    // 512 characters, more than 512 bytes: within the receiver's limit.
    let wide = format!("https://example.com/{}", "é".repeat(492));
    let artifact = |value: &str| SessionArtifact {
        kind: "pull_request".into(),
        value: value.into(),
    };
    let mut item = tests::sample_session_artifact_item();
    item.session_artifacts.push(artifact(&wide));
    // The body that goes out: the over-limit link is left off.
    let before = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    item.session_artifacts.push(artifact(&long));
    let mut items = vec![item];
    apply_upload_policy(SnapshotSource::ClaudeCode, &mut items, all(true));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].session_artifacts.len(), 2);
    assert!(items[0].session_artifacts[0].value.len() <= 512);
    assert_eq!(items[0].session_artifacts[1].value, wide);
    assert_eq!(items[0].snapshot_fingerprint, before, "names the sent body");
}
