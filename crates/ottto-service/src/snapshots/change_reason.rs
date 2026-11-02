//! The selection-time first cause of a file read, for the daemon-local
//! change-reason counts. It reads only persisted state the gate already
//! decided on and never changes a decision.
use super::*;
use crate::local_resource_diagnostics::change_reason::{self as counts, Token};

impl ScanIndex {
    /// Tag a file the scan is about to read with its first cause.
    pub(super) fn note_change_reason_selected(
        &self,
        source: SnapshotSource,
        candidate: &CandidateFile,
        reason: Option<CandidateParseReason>,
    ) {
        let key = local_index_key(&candidate.path);
        let (token, sidecar) =
            self.change_reason(source, &key, &candidate.source_file_fingerprint, reason);
        counts::selected(source.api_slug(), key, token, sidecar);
    }

    /// `(first cause, sidecar_or_fingerprint)`. `SourceChanged` labels three
    /// causes: a pending copy removal, a moved fingerprint (sidecars, launcher
    /// context, scan identity) and an account memo-miss.
    fn change_reason(
        &self,
        source: SnapshotSource,
        key: &str,
        source_file_fingerprint: &str,
        reason: Option<CandidateParseReason>,
    ) -> (Token, bool) {
        use CandidateParseReason as R;
        let receipt_context = || {
            self.files
                .get(key)
                .and_then(|entry| entry.upload_context_receipt.as_ref())
                .map(|receipt| receipt.context_fingerprint.as_str())
        };
        let token = match reason {
            Some(R::TranscriptChanged) => Token::Append,
            Some(R::NewFile) => counts::new_file_token(source.api_slug()),
            Some(R::TerminalDisposition | R::LegacyIdentity) => Token::ParserRevision,
            Some(R::AuthorityQuarantine | R::ForcedFamily) => Token::CopyOwnership,
            Some(R::ActivityOrQuarantineRetry) => Token::AckRecovery,
            Some(R::BodyWitnessAdoption) => self.revision_change_reason(key),
            Some(R::UploadContext)
                if self
                    .upload_context_proof
                    .privacy_turned_off_since(receipt_context()) =>
            {
                Token::PrivacyOffErase
            }
            Some(R::SourceChanged)
                if self
                    .claude_copy_removals
                    .pending(claude_money_birth_store::location_key(key)) =>
            {
                Token::CopyOwnership
            }
            Some(R::SourceChanged)
                if self.files.get(key).is_some_and(|entry| {
                    entry.source_file_fingerprint != source_file_fingerprint
                }) =>
            {
                return (Token::AdminOther, true);
            }
            _ => Token::AdminOther,
        };
        (token, false)
    }

    /// An operator re-owe (`REOWED`) is exact; otherwise an owed revision
    /// whose policy row carries a money rule is a finalizer revision.
    fn revision_change_reason(&self, key: &str) -> Token {
        let marks = self
            .claude_money_birth_store
            .money_marks(claude_money_birth_store::location_key(key));
        if marks & claude_copy_prefix_reread::REOWED != 0 {
            return Token::OperatorRepair;
        }
        let stored = self
            .files
            .get(key)
            .map_or(0, |entry| entry.effective_upload_body_witness_revision);
        let money = self.active_effective_upload_body_witness_revision_monotone
            && (stored.saturating_add(1)..=self.active_effective_upload_body_witness_revision).any(
                |revision| {
                    claude_history_upgrade::revision_policy(revision)
                        .is_some_and(|policy| policy.money_rule)
                },
            );
        if money {
            Token::FinalizerRevision
        } else {
            Token::AdminOther
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] Each main selection path tags its emitted changed body
    /// with exactly one first cause, from selection through read and upload.
    #[test]
    fn each_selection_path_tags_one_changed_body_once() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        use CandidateParseReason as R;
        let key = "/synthetic/one.jsonl";
        let entity = "a".repeat(64);
        let tail = ReadMode::Tail;
        let reset = ReadMode::Full(FullReason::SameSizeEdit);
        type Setup = fn(&mut ScanIndex);
        let none: Setup = |_| {};
        let cases: [(R, Setup, ReadMode, &str); 11] = [
            (R::TranscriptChanged, none, tail, "append"),
            (R::TranscriptChanged, none, reset, "source_reset"),
            (R::TerminalDisposition, none, tail, "parser_revision"),
            (R::ForcedFamily, none, tail, "copy_ownership"),
            (R::Audit, none, tail, "admin_other"),
            (
                R::NewFile,
                |_| counts::index_loaded("claude_code", true, Some(PriorHistory::Moved)),
                tail,
                "destination_bootstrap",
            ),
            (
                R::BodyWitnessAdoption,
                |index| {
                    index.active_effective_upload_body_witness_revision = 3;
                    index.active_effective_upload_body_witness_revision_monotone = true;
                    index
                        .files
                        .get_mut("/synthetic/one.jsonl")
                        .unwrap()
                        .effective_upload_body_witness_revision = 2;
                },
                tail,
                "finalizer_revision",
            ),
            (
                R::BodyWitnessAdoption,
                |index| {
                    index
                        .claude_money_birth_store
                        .set_money_marks("/synthetic/one.jsonl", claude_copy_prefix_reread::REOWED);
                },
                tail,
                "operator_repair",
            ),
            (
                R::UploadContext,
                |index| {
                    let inputs = || UploadContextInputs::new(b"{}", None, false, false, true);
                    index.activate_upload_context("b".repeat(64));
                    index.note_upload_context_inputs(
                        SnapshotSource::ClaudeCode,
                        inputs(),
                        SnapshotUploadPolicy::default(),
                    );
                    index.activate_upload_context("c".repeat(64));
                    index.note_upload_context_inputs(
                        SnapshotSource::ClaudeCode,
                        inputs(),
                        SnapshotUploadPolicy {
                            session_titles_enabled: false,
                            ..SnapshotUploadPolicy::default()
                        },
                    );
                    index
                        .files
                        .get_mut("/synthetic/one.jsonl")
                        .unwrap()
                        .upload_context_receipt = Some(upload_context_receipt::Receipt {
                        context_fingerprint: "b".repeat(64),
                        replay_generation: 0,
                        source_witness: "d".repeat(64),
                        body_witness: "e".repeat(64),
                    });
                },
                tail,
                "privacy_off_erase",
            ),
            (R::UploadContext, none, tail, "admin_other"),
            (
                R::SourceChanged,
                |index| {
                    index
                        .files
                        .get_mut("/synthetic/one.jsonl")
                        .unwrap()
                        .source_file_fingerprint = "moved".into();
                },
                tail,
                "admin_other",
            ),
        ];
        for (reason, setup, mode, expected) in cases {
            let mut index = ScanIndex::default();
            index.files.insert(key.into(), ScanIndexEntry::default());
            index
                .file_snapshot_fingerprints
                .insert(key.into(), BTreeSet::from([entity.clone()]));
            setup(&mut index);
            let (token, _) = index.change_reason(SnapshotSource::ClaudeCode, key, "", Some(reason));
            counts::selected("claude_code", key.into(), token, false);
            counts::read("claude_code", key, mode, 10, 2);
            counts::propagate("claude_code", &index);
            counts::attempted("claude_code", &entity, None, None, 7);
            counts::attempted("claude_code", &entity, None, None, 7);
            let page = serde_json::to_value(counts::drain("claude_code").unwrap()).unwrap();
            let upload = page["upload"].as_object().unwrap();
            assert_eq!(upload.len(), 1, "{reason:?}");
            assert_eq!(upload[expected]["entities"], 1, "{reason:?}");
            assert_eq!(page["read"][expected].as_object().unwrap().len(), 1);
            counts::index_loaded("claude_code", false, None);
        }
    }
}
