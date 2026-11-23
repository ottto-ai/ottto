//! Repair episodes: local observation, independent of verification health.
use std::collections::{BTreeMap, BTreeSet};

use ottto_core::account_store::LocalTrackingConfirmation;
use ottto_protocol::{SourceKind, TrackingConfirmation, TrackingConfirmationState};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{source_slug, LocalApiError, LocalDaemon};

#[derive(Debug, Clone, Default)]
pub(super) struct TrackingEpisodes {
    next_generation: u64,
    // Keep stops until a positive hint so Repair cannot arm an unresolvable wait.
    policy_stopped: BTreeSet<String>,
    episodes: BTreeMap<String, (u64, LocalTrackingConfirmation)>,
}

impl TrackingEpisodes {
    pub(super) fn restore(&mut self, source: &SourceKind, saved: LocalTrackingConfirmation) {
        self.next_generation += 1;
        self.episodes.insert(
            source_slug(source).to_string(),
            (self.next_generation, saved),
        );
    }

    pub(super) fn arm(&mut self, source: &SourceKind, since: String, eligible: bool) {
        self.clear(source);
        if eligible && self.policy_allows(source) {
            self.restore(
                source,
                LocalTrackingConfirmation {
                    since,
                    confirmed_at: None,
                },
            );
        }
    }

    pub(super) fn saved(&self, source: &SourceKind) -> Option<&LocalTrackingConfirmation> {
        self.episodes
            .get(source_slug(source))
            .map(|(_, saved)| saved)
    }

    pub(super) fn pending(&self, source: &SourceKind) -> Option<(u64, String)> {
        self.episodes
            .get(source_slug(source))
            .filter(|(_, saved)| saved.confirmed_at.is_none())
            .map(|(generation, saved)| (*generation, saved.since.clone()))
    }

    fn confirm(&mut self, source: &SourceKind, generation: u64, at: &str) -> bool {
        let Some((current, saved)) = self.episodes.get_mut(source_slug(source)) else {
            return false;
        };
        if *current != generation || saved.confirmed_at.is_some() {
            return false;
        }
        saved.confirmed_at = Some(at.to_string());
        true
    }

    pub(super) fn confirm_smoke(
        &mut self,
        result: &ottto_protocol::SourceVerificationResult,
        generation: u64,
        smoke_after: &str,
    ) -> bool {
        let since = self
            .saved(&result.source)
            .and_then(|saved| parse(&saved.since));
        let at = result.last_received_at.as_deref();
        let fresh = since
            .zip(parse(smoke_after))
            .zip(at.and_then(parse))
            .is_some_and(|((since, after), at)| after >= since && at > since);
        result.verified
            && result.records_seen > 0
            && fresh
            && at.is_some_and(|at| self.confirm(&result.source, generation, at))
    }

    pub(super) fn clear(&mut self, source: &SourceKind) -> bool {
        self.episodes.remove(source_slug(source)).is_some()
    }

    pub(super) fn clear_all(&mut self) {
        self.episodes.clear();
        self.policy_stopped.clear();
    }

    pub(super) fn record_policy(
        &mut self,
        source: &SourceKind,
        window: u64,
        enabled: bool,
    ) -> bool {
        if window == 0 || !enabled {
            self.policy_stopped.insert(source_slug(source).to_string());
            self.clear(source)
        } else {
            self.policy_stopped.remove(source_slug(source));
            false
        }
    }

    pub(super) fn policy_allows(&self, source: &SourceKind) -> bool {
        !self.policy_stopped.contains(source_slug(source))
    }

    pub(super) fn project(
        &self,
        source: &SourceKind,
        applicable: bool,
    ) -> Option<TrackingConfirmation> {
        self.saved(source)
            .filter(|_| applicable && self.policy_allows(source))
            .map(|saved| TrackingConfirmation {
                state: if saved.confirmed_at.is_some() {
                    TrackingConfirmationState::Confirmed
                } else {
                    TrackingConfirmationState::Waiting
                },
                since: saved.since.clone(),
                confirmed_at: saved.confirmed_at.clone(),
            })
    }
}

fn parse(at: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(at, &Rfc3339).ok()
}

/// Reuse reconciliation's parsed values; a changed value need not advance its watermark.
pub(crate) fn parsed_activity_witness(
    since: Option<OffsetDateTime>,
    new: OffsetDateTime,
    previous: Option<OffsetDateTime>,
    within_ceiling: bool,
) -> Option<OffsetDateTime> {
    (since.is_some_and(|since| new > since) && within_ceiling && previous != Some(new))
        .then_some(new)
}

impl LocalDaemon {
    pub(crate) fn arm_tracking_confirmation(
        &self,
        source: &SourceKind,
        plan: &ottto_protocol::RepairPlan,
    ) -> Result<(), LocalApiError> {
        use ottto_protocol::RepairPlanStatus;
        if plan.dry_run
            || !matches!(
                plan.status,
                RepairPlanStatus::Succeeded
                    | RepairPlanStatus::Running
                    | RepairPlanStatus::Proposed
            )
        {
            return Ok(());
        }
        // Observation must not change the outcome of an already completed Repair.
        // An unreadable grant cannot authorize a waiting episode.
        let device = ottto_core::FileDeviceStore::default().load().ok().flatten();
        let eligible = device.as_ref().is_some_and(|device| {
            crate::snapshot_sync::enabled_snapshot_sources(device)
                .contains(&crate::snapshot_sync::snapshot_source_of_kind(source))
        });
        let mut state = self.state()?;
        state.registered_source_grants = device.map(|d| d.sources).unwrap_or_default();
        state
            .tracking_confirmation
            .arm(source, crate::current_rfc3339_timestamp(), eligible);
        state.persist_source_state(source);
        Ok(())
    }

    pub(crate) fn tracking_episode(&self, source: &SourceKind) -> Option<(u64, String)> {
        self.read_tracking_episode(source).ok().flatten()
    }

    /// Like `tracking_episode`, but an unreadable state is an error, not "none".
    pub(crate) fn read_tracking_episode(
        &self,
        source: &SourceKind,
    ) -> Result<Option<(u64, String)>, LocalApiError> {
        Ok(self.state()?.tracking_confirmation.pending(source))
    }

    pub(crate) fn confirm_tracking_activity(
        &self,
        source: &SourceKind,
        generation: u64,
        at: &str,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.tracking_confirmation.confirm(source, generation, at) {
            state.persist_source_state(source);
        }
        Ok(())
    }

    pub(crate) fn confirm_tracking_smoke(
        &self,
        result: &ottto_protocol::SourceVerificationResult,
        generation: u64,
        smoke_after: &str,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state
            .tracking_confirmation
            .confirm_smoke(result, generation, smoke_after)
        {
            state.persist_source_state(&result.source);
        }
        Ok(())
    }

    pub(crate) fn clear_tracking_confirmation(
        &self,
        source: &SourceKind,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.tracking_confirmation.clear(source) {
            state.persist_source_state(source);
        }
        Ok(())
    }

    pub(crate) fn record_source_grants(
        &self,
        device: &ottto_core::LocalDeviceBinding,
    ) -> Result<(), LocalApiError> {
        let eligible = crate::snapshot_sync::enabled_snapshot_sources(device);
        let mut state = self.state()?;
        state.registered_source_grants.clone_from(&device.sources);
        for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
            if !eligible.contains(&crate::snapshot_sync::snapshot_source_of_kind(&source)) {
                crate::snapshot_sync::reset_collection_health(
                    crate::snapshot_sync::snapshot_source_of_kind(&source),
                );
                if state.tracking_confirmation.clear(&source) {
                    state.persist_source_state(&source);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{SourceVerificationResult, TrackingConfirmationState};

    const SINCE: &str = "2026-11-15T10:00:00Z";
    const AFTER: &str = "2026-11-15T10:01:00Z";

    fn episodes(source: &SourceKind) -> TrackingEpisodes {
        let mut episodes = TrackingEpisodes::default();
        episodes.arm(source, SINCE.into(), true);
        episodes
    }

    #[test]
    fn parsed_activity_filters_each_candidate_and_latches_across_all_sources() {
        for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
            let mut episodes = episodes(&source);
            let (generation, _) = episodes.pending(&source).unwrap();
            let since = parse(SINCE);
            let after = parse(AFTER).unwrap();
            assert_eq!(
                parsed_activity_witness(since, since.unwrap(), None, true),
                None
            );
            assert_eq!(
                parsed_activity_witness(since, parse("2026-11-16T10:00:00Z").unwrap(), None, false),
                None
            );
            let witness = parsed_activity_witness(since, after, None, true).unwrap();
            assert_eq!(witness, after);
            assert!(episodes.confirm(&source, generation, &witness.format(&Rfc3339).unwrap()));
            assert!(!episodes.confirm(&source, generation, "2026-11-15T10:02:00Z"));
            assert_eq!(
                episodes
                    .project(&source, true)
                    .unwrap()
                    .confirmed_at
                    .as_deref(),
                Some(AFTER)
            );
            episodes.arm(&source, AFTER.into(), true);
            assert_eq!(episodes.pending(&source).unwrap().1, AFTER);
        }
    }

    #[test]
    fn ineligible_arm_and_both_policy_stops_clear_and_suppress() {
        let source = SourceKind::Pi;
        let mut episodes = episodes(&source);
        assert!(episodes.project(&source, false).is_none());
        episodes.arm(&source, AFTER.into(), false);
        assert!(episodes.saved(&source).is_none());
        for (window, enabled) in [(0, true), (30, false)] {
            episodes.arm(&source, SINCE.into(), true);
            assert!(episodes.record_policy(&source, window, enabled));
            assert!(episodes.project(&source, true).is_none());
            episodes.arm(&source, AFTER.into(), true);
            assert!(episodes.saved(&source).is_none());
            episodes.record_policy(&source, 30, true);
        }
    }

    fn verification() -> SourceVerificationResult {
        serde_json::from_value(serde_json::json!({
            "source": "claude_code", "config": {"discovered": true, "path_hint": null, "fingerprint": null, "drift": []},
            "status": "verified", "verified": true, "records_seen": 1,
            "last_record_id": null, "last_received_at": AFTER, "smoke_after": SINCE,
            "message": {"code": "verified", "text": "Verified"}, "route_results": []
        })).unwrap()
    }

    #[test]
    fn active_smoke_requires_own_fresh_records_and_current_generation() {
        let source = SourceKind::ClaudeCode;
        let mut episodes = episodes(&source);
        let (old_generation, _) = episodes.pending(&source).unwrap();
        episodes.arm(&source, SINCE.into(), true); // two Repairs in the same second
        episodes.confirm_smoke(&verification(), old_generation, SINCE);
        assert!(episodes.saved(&source).unwrap().confirmed_at.is_none());
        let (generation, _) = episodes.pending(&source).unwrap();
        let mut quota_warning = verification();
        quota_warning.verified = false;
        quota_warning.records_seen = 0;
        episodes.confirm_smoke(&quota_warning, generation, SINCE);
        quota_warning.verified = true; // identity-only / local-only warning
        episodes.confirm_smoke(&quota_warning, generation, SINCE);
        episodes.confirm_smoke(&verification(), generation, "2026-11-15T09:59:59Z");
        assert!(episodes.saved(&source).unwrap().confirmed_at.is_none());
        episodes.confirm_smoke(&verification(), generation, SINCE);
        assert_eq!(
            episodes.project(&source, true).unwrap().state,
            TrackingConfirmationState::Confirmed
        );
    }

    #[test]
    fn persisted_episode_restores_without_a_serialized_generation() {
        let source = SourceKind::Codex;
        let mut episodes = episodes(&source);
        let json = serde_json::to_value(episodes.saved(&source).unwrap()).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 2);
        episodes.clear_all();
        episodes.restore(&source, serde_json::from_value(json).unwrap());
        assert_eq!(
            episodes.project(&source, true).unwrap().state,
            TrackingConfirmationState::Waiting
        );
        let wire = serde_json::to_value(episodes.project(&source, true).unwrap()).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 3);
        assert!(wire["confirmed_at"].is_null());
        let unknown: TrackingConfirmation = serde_json::from_value(
            serde_json::json!({"state": "future", "since": SINCE, "confirmed_at": null}),
        )
        .unwrap();
        assert_eq!(unknown.state, TrackingConfirmationState::Unknown);
    }
}
