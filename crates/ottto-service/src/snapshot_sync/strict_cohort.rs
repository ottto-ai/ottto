//! Bounded service of pending strict roots. Omitted roots are debt, not absence.
use super::*;
pub(super) const ROOTS_PER_PASS: usize = 128;
pub(super) const BYTES_PER_PASS: u64 = 16 * 1024 * 1024;
pub(super) struct Plan {
    pub roots: Vec<String>,
    pub deferred: BTreeSet<String>,
    pub deferred_bytes: u64,
    /// Pass read allowance: the plan's reservation, never below BYTES_PER_PASS.
    pub allowance: u64,
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
            allowance: BYTES_PER_PASS,
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
        allowance: BYTES_PER_PASS,
    };
    let mut reserved = 0u64;
    let mut next = None;
    for root in ordered {
        let bytes = crate::claude_local_otel::strict_cohort_bytes(support, root);
        // The first off-page root after the cursor is planned even over the
        // pass allowance (per-file caps still bound it), so none waits forever.
        let first_offpage = !page.contains(root) && next.is_none();
        if first_offpage {
            next = Some(root.clone());
        }
        // Page roots are never deferred here: the reader's allowance defers a
        // read it cannot cover through the #932 hold, never as unhealthy.
        if page.contains(root)
            || first_offpage
            || plan.roots.len() < ROOTS_PER_PASS && reserved.saturating_add(bytes) <= BYTES_PER_PASS
        {
            reserved = reserved.saturating_add(bytes);
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
    plan.allowance = reserved.max(BYTES_PER_PASS);
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [behaviour] Containment contract: strict cohort bounds many offpage roots and continues.
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

    /// Sparse API and trace sidecars of the given lengths for `root`.
    fn write_pair(support: &Path, root: &str, api: u64, trace: u64) {
        let name = format!("{:x}.jsonl", Sha256::digest(root.as_bytes()));
        for (store, len) in [
            ("local-otel/claude-code-effort", api),
            ("local-otel/claude-code-trace-ownership", trace),
        ] {
            let dir = support.join(store);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::File::create(dir.join(&name))
                .unwrap()
                .set_len(len)
                .unwrap();
        }
    }

    /// [behaviour] X1: a page root whose pair exceeds the pass allowance is
    /// planned, and a strict read the allowance cannot cover is deferred to
    /// the #932 hold (a trace cap discard, or the pass's deferred API read),
    /// never only an oversized file. OFF rows are main: only oversized.
    #[test]
    fn strict_allowance_shortfall_defers_page_root_through_discard() {
        // (terminal_off, the API sidecar is over the allowance, else the trace)
        for (terminal_off, api_over) in [(true, false), (false, false), (true, true), (false, true)]
        {
            let _terminal_off =
                terminal_off.then(crate::snapshots::ClaudeTerminalOffForTest::enabled);
            let scratch = crate::test_scratch::ScratchDir::new("strict-allowance-shortfall");
            let over = BYTES_PER_PASS + 1;
            let (api_len, trace_len) = if api_over { (over, 0) } else { (0, over) };
            write_pair(&scratch, "page-small", 0, 0);
            write_pair(&scratch, "page-over", api_len, trace_len);
            let roots = vec!["page-over".to_string(), "page-small".to_string()];
            let page = roots.iter().cloned().collect::<BTreeSet<_>>();
            let planned = plan(&scratch, roots.clone(), &page, "shortfall");
            assert_eq!(planned.roots, roots, "terminal_off={terminal_off}");
            assert!(planned.deferred.is_empty(), "terminal_off={terminal_off}");

            let row = format!("terminal_off={terminal_off} api_over={api_over}");
            let allowance =
                crate::claude_local_otel::strict_budget::StrictReadBudget::new(BYTES_PER_PASS);
            let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
                &scratch,
                ["page-over".to_string()],
            );
            let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                &scratch,
                ["page-over".to_string()],
            );
            // The short read is never complete or absent evidence.
            assert_eq!(api.health.is_complete(), !api_over, "{row}");
            // OFF (main) bounds the API read by the per-file cap only.
            assert_eq!(
                api.health.oversized_files,
                u64::from(terminal_off && api_over),
                "{row}"
            );
            assert_eq!(trace.is_complete(), api_over, "{row}");
            assert_eq!(trace.oversized_files, u64::from(!api_over), "{row}");
            assert_eq!(
                trace.rows_discarded,
                crate::claude_local_otel::ClaudeTraceRowsDiscarded {
                    cap: u64::from(terminal_off && !api_over),
                    ..Default::default()
                },
                "{row}"
            );
            assert_eq!(
                allowance.deferred("page-over"),
                terminal_off && api_over,
                "{row}"
            );
        }
    }

    /// [behaviour] X2: a root whose pair alone exceeds the pass allowance is
    /// planned on its page, or as the first off-page root after the cursor,
    /// instead of being deferred on every pass. The OFF row is main.
    #[test]
    fn strict_cohort_plans_root_over_pass_allowance() {
        // (terminal_off, page roots, planned, deferred, pass allowance). A
        // pair reserves its lengths plus one sentinel per file: big = 18 MiB + 2.
        type Row = (
            bool,
            &'static [&'static str],
            &'static [&'static str],
            &'static [&'static str],
            u64,
        );
        let big = (18 << 20) + 2;
        let rows: [Row; 4] = [
            (
                true,
                &["big", "page"],
                &["big", "page", "tail"],
                &[],
                big + 4,
            ),
            (true, &["page"], &["page", "big"], &["tail"], big + 2),
            (true, &["tail"], &["tail", "big"], &["page"], big + 2),
            (
                false,
                &["page"],
                &["big", "page", "tail"],
                &[],
                BYTES_PER_PASS,
            ),
        ];
        for (terminal_off, page, planned, deferred, allowance) in rows {
            let _terminal_off =
                terminal_off.then(crate::snapshots::ClaudeTerminalOffForTest::enabled);
            let scratch = crate::test_scratch::ScratchDir::new("strict-cohort-big-root");
            write_pair(&scratch, "big", 10 << 20, 8 << 20);
            write_pair(&scratch, "page", 0, 0);
            write_pair(&scratch, "tail", 0, 0);
            let roots = ["big", "page", "tail"].map(String::from).to_vec();
            let page = page.iter().map(|r| r.to_string()).collect::<BTreeSet<_>>();
            let result = plan(&scratch, roots, &page, "big-root");
            assert_eq!(
                result.roots, planned,
                "terminal_off={terminal_off} page={page:?}"
            );
            assert_eq!(
                result.deferred.iter().collect::<Vec<_>>(),
                deferred,
                "terminal_off={terminal_off} page={page:?}"
            );
            assert_eq!(
                result.allowance, allowance,
                "the reader allowance covers the reservation"
            );
        }
    }
}
