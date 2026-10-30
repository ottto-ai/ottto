//! Bounded service of pending strict roots. Omitted roots are debt, not absence.
use super::*;
pub(super) const ROOTS_PER_PASS: usize = 128;
pub(super) const BYTES_PER_PASS: u64 = 16 * 1024 * 1024;
pub(super) struct Plan {
    pub roots: Vec<String>,
    pub deferred: BTreeSet<String>,
    pub deferred_bytes: u64,
}
// A normal source cycle reloads ScanIndex. Keep scheduling in bounded
// process-owned memory, scoped to support directory + active context/replay.
// Eviction/restart only revisits a prefix; neither grants nor drops evidence.
static CURSORS: std::sync::Mutex<VecDeque<(String, Option<String>)>> =
    std::sync::Mutex::new(VecDeque::new());
const CURSOR_SCOPES: usize = 64;
pub(super) fn plan(
    support: &Path,
    roots: Vec<String>,
    page: &BTreeSet<String>,
    scope: &str,
) -> Plan {
    if !crate::snapshots::claude_terminal_off() {
        return Plan {
            roots,
            deferred: BTreeSet::new(),
            deferred_bytes: 0,
        };
    }

    let key = format!(
        "{:x}",
        Sha256::digest(format!("{}:{scope}", support.display()).as_bytes())
    );
    let mut cursors = CURSORS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cursor = cursors
        .iter()
        .position(|(saved, _)| saved == &key)
        .and_then(|at| cursors.remove(at))
        .and_then(|(_, cursor)| cursor);
    let result = select(support, roots, page, &mut cursor);
    if cursors.len() >= CURSOR_SCOPES {
        cursors.pop_front();
    }
    cursors.push_back((key, cursor));
    result
}
fn select(
    support: &Path,
    roots: Vec<String>,
    page: &BTreeSet<String>,
    cursor: &mut Option<String>,
) -> Plan {
    let after = cursor.as_deref();
    let mut ordered = roots
        .iter()
        .filter(|r| page.contains(*r))
        .collect::<Vec<_>>();
    ordered.extend(
        roots
            .iter()
            .filter(|r| !page.contains(*r) && after.map_or(true, |a| r.as_str() > a)),
    );
    ordered.extend(
        roots
            .iter()
            .filter(|r| !page.contains(*r) && after.is_some_and(|a| r.as_str() <= a)),
    );
    let mut plan = Plan {
        roots: Vec::new(),
        deferred: BTreeSet::new(),
        deferred_bytes: 0,
    };
    let mut reserved = 0u64;
    let mut next = None;
    for root in ordered {
        let bytes = crate::claude_local_otel::strict_cohort_bytes(support, root);
        if !page.contains(root) && next.is_none() {
            next = Some(root.clone());
        }
        if plan.roots.len() < ROOTS_PER_PASS && reserved.saturating_add(bytes) <= BYTES_PER_PASS {
            reserved += bytes;
            plan.roots.push(root.clone());
            if !page.contains(root) {
                next = Some(root.clone());
            }
        } else {
            plan.deferred.insert(root.clone());
            plan.deferred_bytes = plan.deferred_bytes.saturating_add(bytes);
        }
    }
    if let Some(next) = next {
        *cursor = Some(next);
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_off_strict_cohort_bounds_many_offpage_roots_and_continues() {
        let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

        let scratch = crate::test_scratch::ScratchDir::new("strict-cohort-service");
        let roots = (0..ROOTS_PER_PASS + 3)
            .map(|n| format!("root-{n:04}"))
            .collect::<Vec<_>>();
        for root in &roots {
            let name = format!("{:x}.jsonl", Sha256::digest(root.as_bytes()));
            for store in [
                "local-otel/claude-code-effort",
                "local-otel/claude-code-trace-ownership",
            ] {
                let dir = scratch.join(store);
                std::fs::create_dir_all(&dir).unwrap();
                let bytes: &[u8] = if root == &roots[1] && store.ends_with("trace-ownership") {
                    b"{}\n"
                } else {
                    b""
                };
                std::fs::write(dir.join(&name), bytes).unwrap();
            }
        }
        let page = BTreeSet::from([roots[0].clone()]);
        let mut index = ScanIndex::default();
        index.activate_upload_context("cohort-context".into());
        let first = plan(
            &scratch,
            roots.clone(),
            &page,
            &index.claude_strict_service_scope(),
        );
        assert_eq!(first.roots.len(), ROOTS_PER_PASS);
        assert_eq!(first.deferred.len(), 3);
        assert_eq!(first.deferred_bytes, 6, "two EOF sentinels per paired root");
        assert!(
            first.roots.contains(&roots[0]),
            "healthy current-page evidence has priority"
        );
        let allowance =
            crate::claude_local_otel::strict_budget::StrictReadBudget::new(BYTES_PER_PASS);
        for root in &first.roots {
            let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
                &scratch,
                [root.clone()],
            );
            let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                &scratch,
                [root.clone()],
            );
            assert!(api.health.is_complete());
            assert_eq!(trace.is_complete(), root != &roots[1]);
        }
        assert_eq!(
            allowance.consumed(),
            3,
            "actual consumed sidecar bytes, not estimated sizes"
        );
        drop(allowance);
        // Production prepare reloads the index every cycle, not only after a
        // daemon restart. This continuation must survive that ordinary load.
        let mut loaded: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        loaded.activate_upload_context("cohort-context".into());
        let second = plan(
            &scratch,
            roots,
            &page,
            &loaded.claude_strict_service_scope(),
        );
        assert!(
            first
                .deferred
                .iter()
                .all(|root| second.roots.contains(root)),
            "off-page debt receives continuation"
        );
    }
}
