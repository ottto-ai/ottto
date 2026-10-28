//! Opportunistic, process-local Desktop request activity. No acquisition or
//! persistence: the existing request fold publishes only validated event clocks.
use ottto_protocol::{AgentStatusSnapshot, SourceKind};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const WINDOW: time::Duration = time::Duration::minutes(15);
const MAX_PAIRS: usize = 64;
static RECENT: Mutex<RecentActivity> = Mutex::new(RecentActivity(BTreeMap::new()));

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecentActivity(BTreeMap<(String, String), OffsetDateTime>);

fn recent(at: OffsetDateTime, now: OffsetDateTime) -> bool {
    at <= now && now - at <= WINDOW
}

impl RecentActivity {
    pub(crate) fn note(
        &mut self,
        account: &str,
        org: &str,
        at: OffsetDateTime,
        now: OffsetDateTime,
    ) {
        let hash = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !hash(account) || !hash(org) || !recent(at, now) {
            return;
        }
        self.0.retain(|_, at| recent(*at, now));
        let key = (account.to_owned(), org.to_owned());
        if let Some(previous) = self.0.get_mut(&key) {
            *previous = (*previous).max(at);
        } else if self.0.len() < MAX_PAIRS {
            self.0.insert(key, at);
        }
    }

    fn overlay(
        &self,
        snapshots: &mut [AgentStatusSnapshot],
        health: &AgentStatusSnapshot,
        now: OffsetDateTime,
    ) {
        // Each Desktop root has its own config-selected account, independent
        // of CLI login and the Desktop collector's inferred current org.
        let accounts: BTreeSet<&str> = health
            .plan_observations
            .iter()
            .filter(|o| {
                o.auth_mode.as_deref() == Some("claude_desktop")
                    && o.evidence_method.as_deref() == Some("claude_desktop_session_bucket")
                    && o.is_current == Some(true)
            })
            .filter_map(|o| o.account_identifier_hash.as_deref())
            .collect();
        for snapshot in snapshots {
            for row in &mut snapshot.plan_observations {
                // Clear even an old decoded/stored value: only process memory
                // may supply this field, and every response evaluates expiry.
                row.desktop_recent_at = None;
                if snapshot.source != SourceKind::ClaudeCode {
                    continue;
                }
                let Some(account) = row.account_identifier_hash.as_deref() else {
                    continue;
                };
                if !accounts.contains(account) {
                    continue;
                }
                let Some(org) = row.organization_identifier_hash.as_deref() else {
                    continue;
                };
                let key = (account.to_owned(), org.to_owned());
                if let Some(at) = self.0.get(&key).filter(|at| recent(**at, now)) {
                    row.desktop_recent_at = at.format(&Rfc3339).ok();
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn at(&self, account: &str, org: &str) -> Option<OffsetDateTime> {
        self.0.get(&(account.to_owned(), org.to_owned())).copied()
    }
}

pub(crate) fn publish(activity: RecentActivity) {
    if activity.0.is_empty() {
        return;
    }
    let now = OffsetDateTime::now_utc();
    let mut saved = RECENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for ((account, org), at) in activity.0 {
        saved.note(&account, &org, at, now);
    }
}

pub(crate) fn overlay(
    snapshots: &mut [AgentStatusSnapshot],
    health: &AgentStatusSnapshot,
    now: OffsetDateTime,
) {
    RECENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .overlay(snapshots, health, now);
}

#[cfg(test)]
pub(crate) fn saved() -> RecentActivity {
    RECENT.lock().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::AgentStatusPlanObservation;

    fn t(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn row(account: &str, org: Option<&str>, selected: bool) -> AgentStatusPlanObservation {
        serde_json::from_value(serde_json::json!({
            "auth_mode": "claude_desktop", "evidence_method": "claude_desktop_session_bucket",
            "account_identifier_hash": account, "organization_identifier_hash": org,
            "is_current": selected, "confidence": "high"
        }))
        .unwrap()
    }

    fn snapshot(rows: Vec<AgentStatusPlanObservation>) -> AgentStatusSnapshot {
        serde_json::from_value(serde_json::json!({
            "source": "claude_code", "status": "available", "collection_method": "manual_fallback",
            "captured_at": "2026-10-25T10:00:00Z", "expires_at": "2026-10-25T10:15:00Z",
            "plan_observations": rows
        }))
        .unwrap()
    }

    #[test]
    fn desktop_recent_window_both_orgs_and_account_isolation() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let x = "c".repeat(64);
        let y = "d".repeat(64);
        let mut activity = RecentActivity::default();
        activity.note(&a, &x, t(1000), t(1900)); // inclusive 15-minute boundary
        activity.note(&a, &y, t(1890), t(1900));
        activity.note(&b, &x, t(1899), t(1900)); // same Team org, different account
        activity.note(&a, &y, t(1901), t(1900)); // future cannot extend evidence
        activity.note(&a, &x, t(999), t(1900)); // stale cannot extend evidence
        let mut snapshots = vec![snapshot(vec![
            row(&a, None, true),
            row(&a, Some(&x), false),
            row(&a, Some(&y), false),
            row(&b, Some(&x), false),
        ])];
        let health = snapshots[0].clone();
        activity.overlay(&mut snapshots, &health, t(1900));
        let rows = &snapshots[0].plan_observations;
        assert!(rows[0].desktop_recent_at.is_none());
        assert!(rows[1].desktop_recent_at.is_some());
        assert!(rows[2].desktop_recent_at.is_some());
        assert!(rows[3].desktop_recent_at.is_none());
        activity.overlay(&mut snapshots, &health, t(1901));
        assert!(snapshots[0].plan_observations[1]
            .desktop_recent_at
            .is_none());
        activity.overlay(&mut snapshots, &health, t(2791));
        assert!(snapshots[0]
            .plan_observations
            .iter()
            .all(|r| r.desktop_recent_at.is_none()));
        // Merely knowing the org never supplies the selected account.
        let mut no_selection = health.clone();
        no_selection.plan_observations[0].is_current = Some(false);
        activity.overlay(&mut snapshots, &no_selection, t(1900));
        assert!(snapshots[0]
            .plan_observations
            .iter()
            .all(|r| r.desktop_recent_at.is_none()));
    }

    #[test]
    fn desktop_recent_uses_health_selection_when_default_upload_is_shadowed() {
        let a = "a".repeat(64);
        let x = "c".repeat(64);
        let mut activity = RecentActivity::default();
        activity.note(&a, &x, t(1000), t(1000));
        // A registered slot owns the metered upload: Desktop config selection
        // is still present in source health, but not in the upload snapshots.
        let health = snapshot(vec![row(&a, None, true)]);
        let mut snapshots = vec![snapshot(vec![row(&a, Some(&x), false)])];
        activity.overlay(&mut snapshots, &health, t(1000));
        assert!(snapshots[0].plan_observations[0]
            .desktop_recent_at
            .is_some());
    }

    #[test]
    fn desktop_recent_marks_each_selected_desktop_account() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let x = "d".repeat(64);
        let y = "e".repeat(64);
        let mut activity = RecentActivity::default();
        for (account, org) in [(&a, &x), (&a, &y), (&b, &x), (&c, &x)] {
            activity.note(account, org, t(1000), t(1000));
        }
        let health = snapshot(vec![
            row(&a, None, true),
            row(&b, None, true),
            row(&a, Some(&x), true), // repeated observation from the same root
            row(&c, None, false),    // old bucket, not a selected Desktop account
        ]);
        let mut snapshots = vec![snapshot(vec![
            row(&a, Some(&x), false),
            row(&a, Some(&y), false),
            row(&b, Some(&x), false),
            row(&b, Some(&y), false), // no request under this org
            row(&c, Some(&x), false),
        ])];
        activity.overlay(&mut snapshots, &health, t(1000));
        assert_eq!(
            snapshots[0]
                .plan_observations
                .iter()
                .map(|r| r.desktop_recent_at.is_some())
                .collect::<Vec<_>>(),
            vec![true, true, true, false, false]
        );
        assert!(snapshots[0]
            .clone()
            .redacted_for_backend()
            .plan_observations
            .iter()
            .all(|r| r.desktop_recent_at.is_none()));
        snapshots[0].source = SourceKind::Pi;
        activity.overlay(&mut snapshots, &health, t(1000));
        assert!(snapshots[0]
            .plan_observations
            .iter()
            .all(|r| r.desktop_recent_at.is_none()));
        snapshots[0].source = SourceKind::ClaudeCode;
        activity.overlay(&mut snapshots, &health, t(1901));
        assert!(snapshots[0]
            .plan_observations
            .iter()
            .all(|r| r.desktop_recent_at.is_none()));
    }

    #[test]
    fn desktop_recent_is_bounded_and_hash_only() {
        let mut activity = RecentActivity::default();
        for i in 0..MAX_PAIRS + 1 {
            activity.note(&"a".repeat(64), &format!("{i:064x}"), t(1000), t(1000));
        }
        assert_eq!(activity.0.len(), MAX_PAIRS);
        activity.note("raw-account", &"b".repeat(64), t(1000), t(1000));
        assert_eq!(activity.0.len(), MAX_PAIRS);
        activity.note(&"a".repeat(64), &"b".repeat(64), t(2000), t(2000));
        assert_eq!(activity.0.len(), 1);
    }
}
