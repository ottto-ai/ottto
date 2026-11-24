//! The owned source scan's page step: one call reads the next page of the
//! selected files, applies it to the index and returns either the scan to
//! resume or the completed result.
//!
//! The driver checks entry conditions and runs Codex planning or active-file
//! work. When both fall through, it dequeues one candidate for selection and
//! start, or closes the page. Every post-entry pause reaches one exit.
#[cfg(test)]
use crate::snapshots::e2_pipeline_scan_fixture::twin_diagnostics;
use crate::snapshots::*;

// Codex disclosures update the same three scan fields. A macro, not a method:
// a method would borrow the whole scan while callers hold other fields.
macro_rules! targets {
    ($scan:ident) => {
        sampled_scan::codex_cursor::DisclosureTargets {
            census: &mut $scan.census,
            residue_index_keys: &mut $scan.residue_index_keys,
            pending_finalization: &mut $scan.pending_finalization,
        }
    };
}

mod codex_join;

mod active_file;

mod select;

mod close;

impl OwnedSourceScan {
    pub(crate) fn step(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> OwnedSourceScanStep {
        self.step_inner(attribution_context)
            .expect("ordinary serial collection is available")
    }
    pub(crate) fn step_fallible(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        state_v2::before_collection(&self.index).map_err(|_| {
            crate::source_rotation::LocalRefusal("state_v2_maintenance_before_collection")
        })?;
        self.step_inner(attribution_context)
    }

    fn step_inner(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let _acquire_window = state_v2::telemetry::acquire_window(&self.index);
        let mut result =
            crate::local_resource_diagnostics::jsonl::page(self.source.api_slug(), || {
                self.step_inner_page(attribution_context)
            });
        match &result {
            Ok(OwnedSourceScanStep::Pending(scan)) => state_v2::telemetry::acquired(&scan.index),
            Ok(OwnedSourceScanStep::Complete { index, .. }) => state_v2::telemetry::acquired(index),
            Err(_) => {}
        }
        let counts = diagnostics.finish();
        if let Ok(OwnedSourceScanStep::Pending(scan)) = &mut result {
            scan.resource_probe.page_events.merge(counts);
        }
        result
    }

    #[inline(never)]
    fn step_inner_page(
        mut self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        if !self.index.persistence_available() {
            return Err(crate::source_rotation::LocalRefusal(
                "scan_index_map_unavailable",
            ));
        }
        if self.walk_idle {
            // The walk gate held this pass: nothing is listed or read.
            let scan = SourceScanResult {
                walk_idle: true,
                backfill_window_days: self.backfill_window_days,
                backfill_file_limit: self.file_limit,
                census_window_end: self.census_window_end,
                ..SourceScanResult::empty(self.source)
            };
            return Ok(OwnedSourceScanStep::Complete {
                index: self.index,
                scan,
            });
        }

        // Prepare one demand batch through bounded native continuations. Group
        // owners come from the completed header census, never arbitrary names.
        if self.active_file.is_none()
            && self.codex_join_active.is_none()
            && (self.source != SnapshotSource::Codex || self.codex_join_prepared)
        {
            let launch_lookup = attribution_context
                .map(|context| context.launch_events())
                .or(self.launch_events.as_deref());
            if let Some(events) = launch_lookup {
                let first = self
                    .codex_join_groups
                    .front()
                    .map(|group| vec![group.owner.clone()])
                    .or_else(|| {
                        self.identified_candidates.front().map(|candidate| {
                            launch_workers_for_candidate(
                                self.source,
                                candidate,
                                self.codex_join_inventory.as_ref(),
                            )
                        })
                    })
                    .unwrap_or_default();
                // A completed batch covers its remaining members. Looking at
                // a sliding window here would add one new worker after every
                // file and repeat the complete retained-store sweep per file.
                if !events.prepared(&first) {
                    let mut workers = BTreeSet::new();
                    for worker in self
                        .codex_join_groups
                        .iter()
                        .map(|group| group.owner.clone())
                        .chain(self.identified_candidates.iter().flat_map(|candidate| {
                            launch_workers_for_candidate(
                                self.source,
                                candidate,
                                self.codex_join_inventory.as_ref(),
                            )
                        }))
                        .take(crate::launch_events::MAX_DEMANDED_WORKERS)
                    {
                        if crate::launch_events::valid_worker(&worker) {
                            workers.insert(worker.to_ascii_lowercase());
                        }
                        if workers.len() == crate::launch_events::MAX_DEMANDED_WORKERS {
                            break;
                        }
                    }
                    let workers = workers.into_iter().collect::<Vec<_>>();
                    match events.prepare_step(&workers) {
                        Ok(false) => return Ok(OwnedSourceScanStep::Pending(self)),
                        Err(()) => {} // Candidate handling keeps unreadable evidence owed.
                        Ok(true) => {}
                    }
                }
            }
        }
        let scan_launch_events = self.launch_events.clone();
        let launch_lookup = attribution_context
            .map(|context| context.launch_events())
            .or(scan_launch_events.as_deref());
        // The parser and lease travel separately during a step. Pair them
        // only when returning a scan that can resume.
        let (mut active_file, mut codex_cursor_lease) =
            std::mem::take(&mut self.active_file).into_parts();

        let paused = self.step_codex_join(launch_lookup, &mut active_file, &mut codex_cursor_lease)
            || self.step_active_file(
                attribution_context,
                &mut active_file,
                &mut codex_cursor_lease,
            )
            || match self.identified_candidates.pop_front() {
                Some(candidate) => {
                    self.select_and_start(
                        candidate,
                        launch_lookup,
                        &mut active_file,
                        &mut codex_cursor_lease,
                    );
                    true
                }
                None => false,
            };
        if paused {
            if let (None, Some(delivery)) = (&active_file, self.line_delivery.as_mut()) {
                delivery.left_active();
            }
            self.active_file =
                sampled_scan::codex_cursor::ActiveFrame::new(active_file, codex_cursor_lease);
            self.walk_idle = false;
            Ok(OwnedSourceScanStep::Pending(self))
        } else {
            // Close owns the detached resources. Its parameters drop the lease
            // and parser before ending any remaining line delivery.
            let line_delivery = self.line_delivery.take();
            Ok(self.close_scan_page(
                line_delivery,
                scan_launch_events,
                active_file,
                codex_cursor_lease,
            ))
        }
    }
}
