use super::*;
use serde_json::Value;

const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];
const START: i64 = 1_788_220_800; // 2026-09-01T00:00:00Z

/// A `days`-long hourly session on the shared wire shape: one row whose
/// account changes daily and one priced row on a fixed account, with exact
/// top rows, scalars and session cost.
fn session(source: SnapshotSource, days: i64) -> SnapshotItem {
    let mut item = crate::snapshots::tests::valid_v6_batch_request()
        .snapshots
        .remove(0);
    item.provenance.collector = format!("{}:synthetic", source.api_slug());
    item.request_evidence.clear();
    let template = item.model_usage[0].clone();
    let row = |model: &str, account: char, tokens: u64, cost: Option<&str>| {
        let mut row = template.clone();
        row.model = model.into();
        row.account_identifier_hash = Some(account.to_string().repeat(64));
        row.evidence_ref = None;
        row.identity_parts = None;
        row.identity_retained = false;
        [row.input_tokens, row.output_tokens, row.request_count] = [tokens, tokens / 2, 1];
        row.cache_read_tokens = 0;
        row.cache_creation_5m_tokens = 0;
        row.cache_creation_1h_tokens = 0;
        row.reasoning_output_tokens = 0;
        row.unattributed_total_tokens = 0;
        row.cost_usd = cost.map(str::to_owned);
        row.input_cost_usd = None;
        row.output_cost_usd = None;
        row.cache_read_cost_usd = None;
        row.cache_creation_cost_usd = None;
        row
    };
    item.usage_buckets = (0..days * 24)
        .map(|hour| {
            let at = rfc3339(START + hour * 3_600).unwrap();
            let account = if (hour / 24) % 2 == 0 { 'a' } else { 'b' };
            SnapshotUsageBucket {
                bucket_start: at.clone(),
                model_usage: vec![
                    row("model-daily", account, 10 + hour as u64, None),
                    row("model-priced", 'c', 7, Some("0.000123")),
                ],
                first_activity_at: Some(at.clone()),
                last_activity_at: Some(at),
            }
        })
        .collect();
    let hours = (days * 24) as u64;
    let daily = (0..hours).map(|hour| 10 + hour).sum::<u64>();
    let mut daily_top = row("model-daily", 'a', daily, None);
    daily_top.output_tokens = (0..hours).map(|hour| (10 + hour) / 2).sum();
    daily_top.request_count = hours;
    daily_top.account_identifier_hash = None;
    let mut priced_top = row("model-priced", 'c', 7 * hours, None);
    priced_top.output_tokens = 3 * hours;
    priced_top.request_count = hours;
    let cost = super::super::usd_picos_string(123_000_000 * u128::from(hours));
    priced_top.cost_usd = Some(cost.clone());
    item.model_usage = vec![daily_top, priced_top];
    item.input_tokens = item.model_usage.iter().map(|row| row.input_tokens).sum();
    item.output_tokens = item.model_usage.iter().map(|row| row.output_tokens).sum();
    item.request_count = 2 * hours;
    [
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.reasoning_output_tokens,
        item.unattributed_total_tokens,
    ] = [0; 5];
    item.cost = Some(SnapshotCost {
        total_cost_usd: Some(cost),
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
        evidence_source: "synthetic".into(),
    });
    item
}

fn now(item: &SnapshotItem) -> i64 {
    bucket_unix(item.usage_buckets.last().unwrap()).unwrap() + 3_600
}

fn cut_of(item: &SnapshotItem) -> Cut {
    Cut::at(now(item))
}

/// Every bucket row as sent, keyed by bucket and model; once per entity.
fn rows(pieces: &[&SnapshotItem]) -> BTreeMap<(String, String), Value> {
    let mut rows = BTreeMap::new();
    for piece in pieces {
        for bucket in &piece.usage_buckets {
            for row in &bucket.model_usage {
                let key = (bucket.bucket_start.clone(), row.model.clone());
                assert!(
                    rows.insert(key, serde_json::to_value(row).unwrap())
                        .is_none(),
                    "a bucket row is in exactly one entity"
                );
            }
        }
    }
    rows
}

fn assert_conserved(full: &SnapshotItem, segments: &[SnapshotItem], live: &SnapshotItem) {
    let pieces = segments.iter().chain([live]).collect::<Vec<_>>();
    assert_eq!(rows(&pieces), rows(&[full]));
    assert_eq!(
        pieces
            .iter()
            .map(|piece| scalars(piece))
            .fold([0u64; 8], |mut sum, values| {
                sum.iter_mut()
                    .zip(values)
                    .for_each(|(sum, value)| *sum += value);
                sum
            }),
        scalars(full)
    );
    for row in &full.model_usage {
        let mut counts = [0u64; 8];
        let mut costs = None::<[Option<u128>; 5]>;
        for top in pieces.iter().flat_map(|piece| &piece.model_usage) {
            if top.model != row.model {
                continue;
            }
            assert_eq!(top.account_identifier_hash, row.account_identifier_hash);
            let part = RowSum::of(top).unwrap();
            counts
                .iter_mut()
                .zip(part.counts)
                .for_each(|(sum, value)| *sum += value);
            costs = Some(match costs {
                None => part.costs,
                Some(sum) => std::array::from_fn(|n| sum[n].zip(part.costs[n]).map(|(a, b)| a + b)),
            });
        }
        let full_row = RowSum::of(row).unwrap();
        assert_eq!((counts, costs), (full_row.counts, Some(full_row.costs)));
    }
    let cost = |piece: &SnapshotItem| {
        wire_usd_picos(
            piece
                .cost
                .as_ref()
                .unwrap()
                .total_cost_usd
                .as_deref()
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        pieces.iter().map(|piece| cost(piece)).sum::<u128>(),
        cost(full)
    );
    for segment in segments {
        assert!(segment.session_account_evidence.is_none());
        assert_eq!(
            serde_json::to_value(&segment.provenance).unwrap(),
            serde_json::to_value(&full.provenance).unwrap()
        );
        assert!(segment.session_display_name.is_none() && segment.attribution_facts.is_empty());
        assert!(segment.context_curve.is_none() && segment.activity_summary.is_none());
        assert_eq!(
            segment.history_segment.as_ref().unwrap().of,
            full.source_session_id
        );
    }
}

/// [money] The shared cut, for every source: each bucket row moves unchanged
/// into exactly one entity, top rows, scalars and session cost conserve,
/// and settled windows are fixed epoch-aligned 7-day windows ending at least
/// 72 h before the pass; the live body keeps no bucket before `through`.
#[test]
fn shared_cut_conserves_money_and_placement_for_every_source() {
    for source in SOURCES {
        let full = session(source, 30);
        let cut = plan(source, &full, TRIGGER_BYTES + 1, cut_of(&full), usize::MAX).unwrap();
        let (segments, live) = split(source, &full, &cut).unwrap();
        assert_eq!(segments.len(), 4, "{source:?}");
        assert_conserved(&full, &segments, &live);
        let through = &live.history_segments.as_ref().unwrap().through;
        assert_eq!(live.history_segments.as_ref().unwrap().count, 4);
        assert_eq!(
            &segments
                .last()
                .unwrap()
                .history_segment
                .as_ref()
                .unwrap()
                .window_end,
            through
        );
        assert!(live
            .usage_buckets
            .iter()
            .all(|bucket| bucket.bucket_start >= *through));
        for segment in &segments {
            let window = segment.history_segment.as_ref().unwrap();
            let start = OffsetDateTime::parse(&window.window_start, &Rfc3339).unwrap();
            let end = OffsetDateTime::parse(&window.window_end, &Rfc3339).unwrap();
            assert_eq!(start.unix_timestamp().rem_euclid(WINDOW_SECONDS), 0);
            assert_eq!((end - start).whole_seconds(), WINDOW_SECONDS);
            assert!(end.unix_timestamp() <= now(&full) - SETTLED_SECONDS);
            assert_eq!(
                segment.source_session_id,
                segment_id(&full.source_session_id, start.unix_timestamp()).unwrap()
            );
            assert!(segment.usage_buckets.iter().all(|bucket| {
                (window.window_start.as_str()..window.window_end.as_str())
                    .contains(&bucket.bucket_start.as_str())
            }));
        }
        // The same full body always cuts the same way (restart recomputes it).
        let again = split(source, &full.clone(), &cut).unwrap();
        assert_eq!(
            serde_json::to_vec(&again).unwrap(),
            serde_json::to_vec(&(segments, live)).unwrap()
        );
    }
}

/// [format] A segment carries only the fields the receiver allows on one:
/// its window's usage, that usage's own request evidence and provenance.
/// Every other field keeps its default; session-level fields (creator
/// evidence included) travel on the live body only.
#[test]
fn segments_carry_only_receiver_segment_fields() {
    const SEGMENT_ITEM_FIELDS: [&str; 22] = [
        "source_session_id",
        "snapshot_fingerprint",
        "status",
        "collected_at",
        "provenance",
        "semantic_envelope",
        "content_hash",
        "history_segment",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "reasoning_output_tokens",
        "unattributed_total_tokens",
        "request_count",
        "usage_accounting_contract",
        "cost",
        "model_usage",
        "usage_buckets",
        "request_evidence",
        "request_identity_refusals",
    ];
    let empty = |value: &Value| match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(values) => values.is_empty(),
        Value::Object(fields) => fields.is_empty(),
    };
    for source in SOURCES {
        let mut full = session(source, 30);
        // Session-level fields a whole body carries.
        full.telemetry_owned_complete = Some(true);
        full.source_file_fingerprint = Some("synthetic-file".into());
        full.source_started_at = Some(full.usage_buckets[0].bucket_start.clone());
        full.source_last_activity_at = Some(full.collected_at.clone());
        let cut = plan(source, &full, TRIGGER_BYTES + 1, cut_of(&full), usize::MAX).unwrap();
        let (segments, live) = split(source, &full, &cut).unwrap();
        assert_eq!(live.copy_unproven_counts, full.copy_unproven_counts);
        assert_eq!(live.source_file_fingerprint, full.source_file_fingerprint);
        for segment in &segments {
            let Value::Object(fields) = serde_json::to_value(segment).unwrap() else {
                panic!("a segment serializes as an object");
            };
            for (name, value) in &fields {
                assert!(
                    SEGMENT_ITEM_FIELDS.contains(&name.as_str()) || empty(value),
                    "{source:?}: {name} belongs to the live body"
                );
            }
        }
    }
}

/// [behaviour] The receiver takes whole 7-day windows only: a window over
/// half the item limit keeps the body whole (never halved); small or recent
/// bodies stay whole.
#[test]
fn shared_cut_keeps_whole_windows_and_skips_small_or_recent_bodies() {
    let codex = SnapshotSource::Codex;
    let full = session(codex, 30);
    let day_bytes = serde_json::to_vec(&full.usage_buckets[..24]).unwrap().len();
    assert!(plan(
        codex,
        &full,
        TRIGGER_BYTES + 1,
        cut_of(&full),
        4 * day_bytes
    )
    .is_none());
    let cut = plan(codex, &full, TRIGGER_BYTES + 1, cut_of(&full), usize::MAX).unwrap();
    for piece in &cut.segments {
        assert_eq!(piece.start.rem_euclid(WINDOW_SECONDS), 0);
        assert_eq!(piece.end - piece.start, WINDOW_SECONDS);
    }
    let (segments, live) = split(codex, &full, &cut).unwrap();
    let ids = segments
        .iter()
        .map(|segment| &segment.source_session_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), segments.len());
    assert_conserved(&full, &segments, &live);
    assert!(plan(codex, &full, TRIGGER_BYTES, cut_of(&full), usize::MAX).is_none());
    let recent = session(codex, 3);
    assert!(plan(
        codex,
        &recent,
        TRIGGER_BYTES + 1,
        cut_of(&recent),
        usize::MAX
    )
    .is_none());
    // Top rows that do not re-sum exactly keep today's whole body.
    let mut unbalanced = full.clone();
    unbalanced.model_usage[1].input_tokens += 1;
    assert!(split(SnapshotSource::Codex, &unbalanced, &cut).is_none());
}

/// [money][regress] A row is priced only when every request in it is
/// priced, while the session total still counts the priced requests. The cut
/// follows that rule instead of leaving the whole body over the limit.
#[test]
fn shared_cut_keeps_partially_priced_rows() {
    for source in SOURCES {
        let mut full = session(source, 30);
        full.usage_buckets[5].model_usage[1].cost_usd = None;
        full.model_usage[1].cost_usd = None;
        let cut = plan(source, &full, TRIGGER_BYTES + 1, cut_of(&full), usize::MAX).unwrap();
        let (segments, live) = split(source, &full, &cut).unwrap();
        assert_eq!(segments.len(), 4, "{source:?}");
        assert_conserved(&full, &segments, &live);
        let priced = |item: &SnapshotItem| {
            item.model_usage
                .iter()
                .find(|row| row.model == "model-priced")
                .and_then(|row| row.cost_usd.clone())
        };
        assert!(priced(&segments[0]).is_none());
        assert!(segments[1..]
            .iter()
            .all(|segment| priced(segment).is_some()));
        assert!(priced(&live).is_some());
    }
}

/// [off=main] Without the capability the page is untouched, byte for byte.
#[test]
fn shared_cut_off_keeps_the_page() {
    let policy = super::super::SnapshotUploadPolicy {
        session_titles_enabled: true,
        workspace_labels_enabled: true,
        session_artifacts_enabled: true,
        session_attribution_enabled: true,
        session_attribution_labels_enabled: true,
    };
    for source in SOURCES {
        let page = (20..)
            .step_by(5)
            .map(|days| vec![session(source, days)])
            .find(|page| {
                super::super::snapshot_item_wire_size(source, &page[0], policy) > TRIGGER_BYTES
            })
            .unwrap();
        let mut off = page.clone();
        expand_page(source, &mut off, None, policy);
        assert_eq!(
            serde_json::to_vec(&off).unwrap(),
            serde_json::to_vec(&page).unwrap()
        );
        let mut on = page.clone();
        expand_page(source, &mut on, Some(cut_of(&page[0])), policy);
        assert!(
            on.len() > 1 && on.last().unwrap().history_segments.is_some(),
            "{source:?}"
        );
    }
}
