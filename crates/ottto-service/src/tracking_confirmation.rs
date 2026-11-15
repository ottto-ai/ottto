//! Repair episodes: local observation, independent of verification health.
use std::collections::{BTreeMap, BTreeSet};

use ottto_core::account_store::LocalTrackingConfirmation;
use ottto_protocol::{SourceKind, TrackingConfirmation, TrackingConfirmationState};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::{source_slug, LocalApiError, LocalDaemon};

#[derive(Debug, Clone, Default)]
pub(super) struct TrackingEpisodes {
    next_generation: u64,
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
        if eligible && !self.policy_stopped.contains(source_slug(source)) {
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
    ) {
        let Some(saved) = self.saved(&result.source) else {
            return;
        };
        if result.verified
            && result.records_seen > 0
            && parse(smoke_after)
                .zip(parse(&saved.since))
                .is_some_and(|(after, since)| after >= since)
        {
            if let Some(at) = result.last_received_at.as_deref().filter(|at| {
                parse(at)
                    .zip(parse(&saved.since))
                    .is_some_and(|(at, since)| at > since)
            }) {
                let at = at.to_string();
                self.confirm(&result.source, generation, &at);
            }
        }
    }

    pub(super) fn clear(&mut self, source: &SourceKind) -> bool {
        self.episodes.remove(source_slug(source)).is_some()
    }

    pub(super) fn clear_all(&mut self) {
        self.episodes.clear();
        self.policy_stopped.clear();
    }

    fn record_policy(&mut self, source: &SourceKind, window: u64, enabled: bool) -> bool {
        if window == 0 || !enabled {
            self.policy_stopped.insert(source_slug(source).to_string());
            self.clear(source)
        } else {
            self.policy_stopped.remove(source_slug(source));
            false
        }
    }

    pub(super) fn project(
        &self,
        source: &SourceKind,
        applicable: bool,
    ) -> Option<TrackingConfirmation> {
        self.saved(source)
            .filter(|_| applicable && !self.policy_stopped.contains(source_slug(source)))
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

/// One scalar per reconcile; never retain per-session confirmation history.
pub(crate) struct ParsedActivityWitness {
    since: Option<OffsetDateTime>,
    ceiling: Option<OffsetDateTime>,
    latest: Option<OffsetDateTime>,
}

impl ParsedActivityWitness {
    pub(crate) fn new(since: Option<&str>, scan_time: &str) -> Self {
        Self {
            since: since.and_then(parse),
            ceiling: parse(scan_time).map(|at| at + Duration::minutes(5)),
            latest: None,
        }
    }

    pub(crate) fn observe(&mut self, new: &str, previous: Option<&str>) {
        let Some(new) = parse(new) else {
            return;
        };
        if self.since.is_some_and(|since| new > since)
            && self.ceiling.is_some_and(|ceiling| new <= ceiling)
            && previous.and_then(parse) != Some(new)
        {
            self.latest = Some(self.latest.map_or(new, |latest| latest.max(new)));
        }
    }

    pub(crate) fn latest(&self) -> Option<String> {
        self.latest.and_then(|at| at.format(&Rfc3339).ok())
    }
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

    pub(crate) fn record_tracking_policy(
        &self,
        source: &SourceKind,
        window: u64,
        enabled: bool,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state
            .tracking_confirmation
            .record_policy(source, window, enabled)
        {
            state.persist_source_state(source);
        }
        Ok(())
    }

    pub(crate) fn tracking_episode(&self, source: &SourceKind) -> Option<(u64, String)> {
        self.state().ok()?.tracking_confirmation.pending(source)
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
        let was_pending = state
            .tracking_confirmation
            .pending(&result.source)
            .is_some();
        state
            .tracking_confirmation
            .confirm_smoke(result, generation, smoke_after);
        if was_pending
            && state
                .tracking_confirmation
                .pending(&result.source)
                .is_none()
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
        let mut state = self.state()?;
        state.registered_source_grants.clone_from(&device.sources);
        for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
            if !crate::snapshot_sync::enabled_snapshot_sources(device)
                .contains(&crate::snapshot_sync::snapshot_source_of_kind(&source))
                && state.tracking_confirmation.clear(&source)
            {
                state.persist_source_state(&source);
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
            let mut witness = ParsedActivityWitness::new(Some(SINCE), AFTER);
            witness.observe(SINCE, None); // strict-after, including index rebuilds
            witness.observe("invalid", None);
            witness.observe("2026-11-16T10:00:00Z", None); // must not mask a valid candidate
            assert_eq!(witness.latest(), None);
            witness.observe(AFTER, None);
            assert_eq!(witness.latest().as_deref(), Some(AFTER));
            assert!(episodes.confirm(&source, generation, &witness.latest().unwrap()));
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
    fn future_previous_value_does_not_poison_a_real_turn_or_mature_unchanged() {
        let future = "2026-11-16T10:00:00Z";
        let mut witness = ParsedActivityWitness::new(Some(SINCE), AFTER);
        witness.observe(AFTER, Some(future)); // same session; stored watermark stays in the future
        assert_eq!(witness.latest().as_deref(), Some(AFTER));
        let mut unchanged = ParsedActivityWitness::new(Some(SINCE), future);
        unchanged.observe(future, Some(future));
        assert_eq!(unchanged.latest(), None);
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
