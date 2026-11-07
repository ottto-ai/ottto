//! Independent Codex contributions. No transcript/proof state is persisted here.
use super::*;

pub(super) fn parser(
    file: File,
    member: &CandidateFile,
    metadata: &CodexTitleMetadata,
    traces: Option<Arc<CodexTurnTraceMap>>,
    index: &ScanIndex,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
) -> std::result::Result<Box<OwnedJsonlParser>, GroupEnd> {
    let input = OpenedInput::encoded(file, &member.path, cache).map_err(|_| GroupEnd::Strict)?;
    let mut parser = OwnedJsonlParser::new_opened(
        input,
        &member.path,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(metadata),
        traces,
    )
    .map_err(|_| GroupEnd::Strict)?;
    codex_counting_version::configure_singleton(&mut parser, member, index);
    Ok(Box::new(parser))
}

macro_rules! counts {
    ($into:expr, $from:expr) => {{
        $into.input_tokens = $from.input_tokens;
        $into.output_tokens = $from.output_tokens;
        $into.cache_read_tokens = $from.cache_read_tokens;
        $into.cache_creation_5m_tokens = $from.cache_creation_5m_tokens;
        $into.cache_creation_1h_tokens = $from.cache_creation_1h_tokens;
        $into.reasoning_output_tokens = $from.reasoning_output_tokens;
        $into.unattributed_total_tokens = $from.unattributed_total_tokens;
        $into.request_count = $from.request_count;
    }};
}

/// Checked conversion of the existing internal decimal-picos projection.
fn typed_cost_picos(text: &str) -> Result<u128> {
    // Internal cost strings were projected from integer picos. This checked
    // typed conversion has no provider field ceiling or rounding policy.
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    anyhow::ensure!(
        !whole.is_empty()
            && fraction.len() <= 12
            && whole
                .bytes()
                .chain(fraction.bytes())
                .all(|byte| byte.is_ascii_digit()),
        "invalid folded typed cost"
    );
    let scale = 10u128.pow((12 - fraction.len()) as u32);
    let whole = whole.parse::<u128>()?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>()?
    };
    whole
        .checked_mul(USD_PICO_SCALE)
        .and_then(|whole| {
            fraction
                .checked_mul(scale)
                .and_then(|fraction| whole.checked_add(fraction))
        })
        .ok_or_else(|| anyhow::anyhow!("folded cost overflow"))
}

fn cost(left: &Option<String>, right: &Option<String>) -> Result<Option<String>> {
    let parse = |value: &Option<String>| -> Result<UsageCosts> {
        Ok(UsageCosts {
            observed: value.is_some(),
            reported: value.is_some(),
            total: value.as_deref().map(typed_cost_picos).transpose()?,
            ..UsageCosts::default()
        })
    };
    let mut sum = parse(left)?;
    let next = parse(right)?;
    sum.add(&next);
    anyhow::ensure!(
        sum.total.is_some() || (left.is_none() && right.is_none()),
        "folded cost overflow"
    );
    Ok(sum.total.map(usd_picos_string))
}

fn merge_rows(into: &mut Vec<SnapshotModelUsage>, rows: Vec<SnapshotModelUsage>) -> Result<()> {
    // Full row identity, including placement and evidence. Raw RowKey alone
    // cannot authorize combining two account/evidence partitions.
    let mut all = BTreeMap::new();
    for row in std::mem::take(into).into_iter().chain(rows) {
        anyhow::ensure!(
            row.identity_parts.is_none() && !row.identity_retained,
            "unsupported folded placement"
        );
        let identity = (
            row_key_from_model_usage(&row),
            row.account_identifier_hash.clone(),
            row.evidence_ref,
            row.copy_invalidated,
        );
        if let Some(previous) = all.get_mut(&identity) {
            let previous: &mut SnapshotModelUsage = previous;
            anyhow::ensure!(
                previous.selector_context == row.selector_context
                    && previous.selector_sources == row.selector_sources,
                "folded selector evidence differs"
            );
            let mut sum = usage_totals_from_model_usage(previous);
            anyhow::ensure!(
                sum.add(&usage_totals_from_model_usage(&row)),
                "folded usage overflow"
            );
            counts!(previous, sum);
            previous.cost_usd = cost(&previous.cost_usd, &row.cost_usd)?;
            previous.input_cost_usd = cost(&previous.input_cost_usd, &row.input_cost_usd)?;
            previous.output_cost_usd = cost(&previous.output_cost_usd, &row.output_cost_usd)?;
            previous.cache_read_cost_usd =
                cost(&previous.cache_read_cost_usd, &row.cache_read_cost_usd)?;
            previous.cache_creation_cost_usd = cost(
                &previous.cache_creation_cost_usd,
                &row.cache_creation_cost_usd,
            )?;
        } else {
            all.insert(identity, row);
        }
    }
    *into = all.into_values().collect();
    Ok(())
}

/// The original member supplies the session metadata/binding. The final member
/// is only the transport carrier. Each file has already finished independently,
/// including its cache detector; never infer adjacency across revert branches.
pub(in crate::snapshots) fn fold(
    last: &mut Vec<SnapshotItem>,
    mut earlier: Vec<SnapshotItem>,
) -> Result<()> {
    anyhow::ensure!(
        last.len() == 1 && !earlier.is_empty(),
        "missing folded member"
    );
    let carrier = last.remove(0);
    let source = carrier.source_file_fingerprint.clone();
    let collected_at = carrier.collected_at.clone();
    let features = (
        carrier.activity_summary.clone(),
        carrier.tool_usage.clone(),
        carrier.tool_usage_truncated,
        carrier.session_artifacts.clone(),
    );
    earlier.push(carrier);
    earlier.sort_by(|a, b| a.source_started_at.cmp(&b.source_started_at));
    let mut iter = earlier.into_iter();
    let mut item = iter.next().expect("original member");
    for next in iter {
        anyhow::ensure!(
            resolve_codex_identity(&item.source_session_id)
                == resolve_codex_identity(&next.source_session_id),
            "folded owner differs"
        );
        // Creator evidence describes the original session start, not a new
        // binding at each revert. Header account compatibility was proved during
        // the full read; preserve each finished row's actual placement here as well.
        let placement = |item: &SnapshotItem| {
            item.model_usage
                .iter()
                .chain(
                    item.usage_buckets
                        .iter()
                        .flat_map(|bucket| &bucket.model_usage),
                )
                .map(|row| row.account_identifier_hash.clone())
                .collect::<BTreeSet<_>>()
        };
        // Creator evidence stays the original's own certified evidence. The raw
        // header pair that admitted an uncertified revert never becomes
        // evidence, and a certified later member under an uncertified
        // original holds rather than leaving the folded body unbound.
        anyhow::ensure!(
            match (
                &item.session_account_evidence,
                &next.session_account_evidence
            ) {
                (_, None) => true,
                (Some(own), Some(next)) => {
                    own.account_identifier_hash == next.account_identifier_hash
                        && own.provider_workspace_hash == next.provider_workspace_hash
                }
                (None, Some(_)) => false,
            },
            "folded creator evidence differs"
        );
        let own_placement = placement(&item);
        anyhow::ensure!(
            own_placement.len() <= 1
                && own_placement == placement(&next)
                && item.request_evidence == next.request_evidence,
            "folded member placement differs"
        );
        let mut sum = usage_totals_from_item(&item);
        anyhow::ensure!(
            sum.add(&usage_totals_from_item(&next)),
            "folded usage overflow"
        );
        counts!(item, sum);
        merge_rows(&mut item.model_usage, next.model_usage)?;
        for bucket in next.usage_buckets {
            if let Some(prior) = item
                .usage_buckets
                .iter_mut()
                .find(|b| b.bucket_start == bucket.bucket_start)
            {
                merge_rows(&mut prior.model_usage, bucket.model_usage)?;
                prior.first_activity_at = prior
                    .first_activity_at
                    .take()
                    .into_iter()
                    .chain(bucket.first_activity_at)
                    .min();
                prior.last_activity_at = prior
                    .last_activity_at
                    .take()
                    .into_iter()
                    .chain(bucket.last_activity_at)
                    .max();
            } else {
                item.usage_buckets.push(bucket);
            }
        }
        match (&mut item.cost, next.cost) {
            (Some(a), Some(b)) => {
                anyhow::ensure!(
                    a.evidence_source == b.evidence_source,
                    "folded cost provenance differs"
                );
                a.total_cost_usd = cost(&a.total_cost_usd, &b.total_cost_usd)?;
                a.input_cost_usd = cost(&a.input_cost_usd, &b.input_cost_usd)?;
                a.output_cost_usd = cost(&a.output_cost_usd, &b.output_cost_usd)?;
                a.cache_read_cost_usd = cost(&a.cache_read_cost_usd, &b.cache_read_cost_usd)?;
                a.cache_creation_cost_usd =
                    cost(&a.cache_creation_cost_usd, &b.cache_creation_cost_usd)?;
            }
            (None, Some(b)) => item.cost = Some(b),
            _ => {}
        }
        match (&mut item.cache_observations, next.cache_observations) {
            (Some(a), Some(b)) => {
                let mut operations = BTreeMap::new();
                for operation in std::mem::take(&mut a.operations)
                    .into_iter()
                    .chain(b.operations)
                {
                    let id = match &operation {
                        cache_observations::Operation::Upsert { observation } => {
                            observation.event_id.clone()
                        }
                        cache_observations::Operation::Retract { event_id } => event_id.clone(),
                    };
                    if let Some(previous) = operations.insert(id, operation.clone()) {
                        anyhow::ensure!(
                            previous == operation,
                            "folded cache observation conflicts"
                        );
                    }
                }
                a.operations = operations.into_values().collect();
                if b.coverage != "complete" {
                    a.coverage = "partial".into();
                }
                if a.coverage != "complete" {
                    a.omitted_observation_count = None;
                }
            }
            _ => item.cache_observations = None,
        }
        item.cache_requests.extend(next.cache_requests);
        item.cache_requests_complete &= next.cache_requests_complete;
        item.source_ended_at = item
            .source_ended_at
            .take()
            .into_iter()
            .chain(next.source_ended_at)
            .max();
        item.source_last_activity_at = item
            .source_last_activity_at
            .take()
            .into_iter()
            .chain(next.source_last_activity_at)
            .max();
    }
    item.usage_buckets
        .sort_by(|a, b| a.bucket_start.cmp(&b.bucket_start));
    (
        item.activity_summary,
        item.tool_usage,
        item.tool_usage_truncated,
        item.session_artifacts,
    ) = features;
    item.source_file_fingerprint = source;
    item.collected_at = collected_at;
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::Codex, &item);
    last.push(item);
    Ok(())
}
