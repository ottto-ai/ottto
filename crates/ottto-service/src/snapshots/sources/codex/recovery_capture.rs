//! Codex recovery capture settlement: once this cycle's upload is accepted,
//! clear each file's captured tier receipt and joined member set when the
//! applied state covers them, and keep them pending otherwise.

use crate::snapshots::*;

impl ScanIndex {
    /// The subset of this scan's index that is safe to commit when the upload
    /// did not finish.
    ///
    /// Committing the whole index after a partial upload would drop every entity
    /// the server never received: the next scan skips an unchanged transcript, so
    /// its snapshot would never be re-derived. Committing nothing is the current
    /// behaviour and is just as wrong in the other direction — a shed request
    /// today means the entire cycle replays, forever, every five minutes.
    ///
    /// An entry is safe when the server demonstrably holds its content:
    ///
    /// * it produced no snapshot at all (nothing to lose), or
    /// * its snapshot was accepted in this pass, or
    /// * its fingerprint is unchanged from the committed index, which is what
    ///   "semantic no-op" means — the server already has that exact content.
    ///
    /// Anything else keeps its previously committed entry, so the next scan
    /// re-parses it and re-uploads. `previous` is the index as loaded from disk,
    /// before this scan mutated it.
    pub(crate) fn reconcile_codex_recovery_settlement(
        &mut self,
        previous: &ScanIndex,
        accepted: &BTreeSet<String>,
    ) {
        for (key, slot) in self.files.slots_mut() {
            let entry = &**slot;
            let settled = self
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|fingerprints| {
                    !fingerprints.is_empty()
                        && fingerprints
                            .iter()
                            .all(|fingerprint| accepted.contains(fingerprint))
                });
            let old = previous.files.get(key);
            let pending_tiers = old.is_some_and(|old| {
                old.codex_captured_tier_receipt_required
                    || old.codex_captured_tier_receipt.is_some()
                    || (old.codex_captured_uncommitted
                        && old.codex_captured_joined_member_set.is_none())
            });
            let pending_join = old.and_then(|old| old.codex_captured_joined_member_set.as_ref());
            let pending_capture = pending_tiers || pending_join.is_some();
            let capture_covered = (!pending_tiers
                || old
                    .and_then(|old| old.codex_captured_tier_receipt.as_ref())
                    .is_some_and(|captured| {
                        entry
                            .codex_applied_tier_receipt
                            .as_ref()
                            .is_some_and(|applied| captured.covered_by(applied))
                    }))
                && pending_join.map_or(true, |captured| {
                    entry
                        .codex_joined_member_set
                        .as_ref()
                        .is_some_and(|applied| {
                            codex_file_join::valid_captured_join(captured)
                                && *captured == codex_file_join::captured_join(applied)
                        })
                });
            if settled && capture_covered {
                if entry.codex_captured_joined_member_set.is_some()
                    || entry.codex_captured_tier_receipt.is_some()
                    || entry.codex_captured_tier_receipt_required
                    || entry.codex_captured_uncommitted
                {
                    let entry = slot.make_mut();
                    entry.codex_captured_joined_member_set = None;
                    entry.codex_captured_tier_receipt = None;
                    entry.codex_captured_tier_receipt_required = false;
                    entry.codex_captured_uncommitted = false;
                }
            } else if pending_capture {
                // Acceptance of an older body cannot settle newly captured facts.
                // A rollback/quarantine must never replace them with an older,
                // smaller applied receipt, or repair missing facts by guessing.
                let captured_receipt = old
                    .and_then(|old| old.codex_captured_tier_receipt.as_ref())
                    .map(|captured| {
                        entry
                            .codex_applied_tier_receipt
                            .as_ref()
                            .filter(|applied| captured.covered_by(applied))
                            .unwrap_or(captured)
                            .clone()
                    });
                let entry = slot.make_mut();
                entry.codex_captured_tier_receipt = captured_receipt;
                entry.codex_captured_joined_member_set = pending_join.cloned();
                entry.codex_captured_tier_receipt_required = pending_tiers;
                entry.codex_captured_uncommitted =
                    old.is_some_and(|old| old.codex_captured_uncommitted);
                entry.codex_applied_tier_receipt =
                    old.and_then(|old| old.codex_applied_tier_receipt.clone());
                entry.codex_applied_tier_receipt_required =
                    old.is_some_and(|old| old.codex_applied_tier_receipt_required);
            }
        }
    }
}
