//! Test-only native builder frozen from main d0dcfbc72 before the copy-family change.
//! Independent decision logic pins the switch-OFF demo output.
use super::*;

impl FileFold {
    pub(super) fn decide_native_pre_change(
        &mut self,
        context: Option<&ReadContext<'_>>,
        markers: Option<&claude_request_identity::OrgMarkers>,
        fork_parent: Option<&str>,
    ) {
        if self.money_birth.uncertain_root() {
            self.disclose("uncertain_birth", self.responses); // counted, disclosed
        }
        if self.copied == 0 {
            self.finish_identity_start(false, markers);
            return;
        }
        // The witness order is total over (effective birth, location), so of
        // two live all-pre-birth paths exactly one is skipped, whatever role
        // (an equal-birth owner can lose to its twin).
        let needs_original = self.first_own.is_none()
            || matches!(self.role, Role::Twin)
            || context.is_some_and(|context| {
                self.location.is_some_and(|Located(location)| {
                    context
                        .index
                        .claude_money_birth_store
                        .staged_location(location)
                })
            });
        let certified = self.money_birth.writer_certified(self.first_own);
        if certified && !needs_original {
            // Timestamp skip: id-less copies stay skipped with the rest.
            self.idless_copy = None;
            self.keep_copies(true, markers);
            return;
        }
        if certified {
            if let Some(witness) = self.original_witness(context) {
                self.proof = Some(CopyProof::Twin(witness));
                self.keep_copies(true, markers);
                return;
            }
        }
        if self.first_own.is_none()
            && self.physical.is_some()
            && self.location.is_some()
            && context.is_some_and(|context| {
                claude_index_path_member_ref(context.path)
                    .is_some_and(|member| member.subagent_stem.is_none())
            })
        {
            // The named original is a sibling file of the same project.
            let parent = fork_parent
                .filter(|parent| !parent.is_empty())
                .zip(context)
                .map(|(parent, context)| {
                    local_index_key(&context.path.with_file_name(format!("{parent}.jsonl")))
                });
            self.proof = Some(CopyProof::Holders(parent));
            // Should the page find no holder, the restored copies keep the
            // accounts their own markers give them (QUOTA: never moved).
            self.keep_copies(false, markers);
            return;
        }
        if let Some(copy) = self.copy.take() {
            self.entity.absorb_grains(&copy);
        }
        if let Some(idless) = self.idless_copy.take() {
            self.entity.absorb_grains(&idless);
        }
        if let Some(accounts) = self.accounts.as_deref_mut() {
            accounts.restore_copies();
        }
        self.entity.removed = Default::default();
        self.entity.removed_requests = 0;
        self.skipped.clear();
        self.disclose("copy_unproven", self.copied);
        self.copied = 0;
        self.finish_identity_start(false, markers);
    }
}
