// Contract-5 request identity: W0 r5 parity, builder, caps and classification.
use super::*;
use crate::snapshots::claude_request_identity::{
    self as identity, AuthorityKey, Contribution, DesktopCensus, MarkerVerdict, Refusal,
    RequestFacts, RequestIdentity, ScanEvidence, Tagged,
};

const W0_DIR: &str = "../../fixtures/session-identity";
const LOGIN_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

fn w0_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(W0_DIR)
        .join(name)
}

fn w0_index() -> Value {
    serde_json::from_slice(&fs::read(w0_path("index.json")).unwrap()).unwrap()
}

/// Every W0 body (old/new/rejected batches and bare P1 items) by name.
fn w0_bodies() -> Vec<(String, Value, Value)> {
    let index = w0_index();
    let mut out = Vec::new();
    for section in ["bodies", "p1_subset"] {
        for (name, entry) in index[section].as_object().unwrap() {
            let file = entry["file"].as_str().unwrap();
            let body: Value = serde_json::from_slice(&fs::read(w0_path(file)).unwrap()).unwrap();
            let item = body
                .get("snapshots")
                .map_or(body.clone(), |snapshots| snapshots[0].clone());
            out.push((name.clone(), item, entry.clone()));
        }
    }
    out
}

fn opt_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn string_map(value: &Value, key: &str) -> BTreeMap<String, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn typed_part(part: &Value) -> SnapshotIdentityPart {
    SnapshotIdentityPart {
        account_identifier_hash: opt_string(part, "account_identifier_hash"),
        evidence_ref: part
            .get("evidence_ref")
            .map(|value| u16::try_from(value.as_u64().unwrap()).unwrap()),
        input_tokens: count(part, "input_tokens"),
        output_tokens: count(part, "output_tokens"),
        cache_read_tokens: count(part, "cache_read_tokens"),
        cache_creation_5m_tokens: count(part, "cache_creation_5m_tokens"),
        cache_creation_1h_tokens: count(part, "cache_creation_1h_tokens"),
        reasoning_output_tokens: count(part, "reasoning_output_tokens"),
        unattributed_total_tokens: count(part, "unattributed_total_tokens"),
        request_count: count(part, "request_count"),
        cost_usd: opt_string(part, "cost_usd"),
        input_cost_usd: opt_string(part, "input_cost_usd"),
        output_cost_usd: opt_string(part, "output_cost_usd"),
        cache_read_cost_usd: opt_string(part, "cache_read_cost_usd"),
        cache_creation_cost_usd: opt_string(part, "cache_creation_cost_usd"),
    }
}

fn typed_row(row: &Value) -> SnapshotModelUsage {
    SnapshotModelUsage {
        model: opt_string(row, "model").unwrap(),
        input_tokens: count(row, "input_tokens"),
        output_tokens: count(row, "output_tokens"),
        cache_read_tokens: count(row, "cache_read_tokens"),
        cache_creation_5m_tokens: count(row, "cache_creation_5m_tokens"),
        cache_creation_1h_tokens: count(row, "cache_creation_1h_tokens"),
        reasoning_output_tokens: count(row, "reasoning_output_tokens"),
        reasoning_effort: opt_string(row, "reasoning_effort"),
        unattributed_total_tokens: count(row, "unattributed_total_tokens"),
        request_count: count(row, "request_count"),
        selector_context: string_map(row, "selector_context"),
        selector_sources: string_map(row, "selector_sources"),
        auth_mode: opt_string(row, "auth_mode"),
        billing_channel: opt_string(row, "billing_channel"),
        billing_provider: opt_string(row, "billing_provider"),
        gateway_provider: opt_string(row, "gateway_provider"),
        model_provider: opt_string(row, "model_provider"),
        subscription_product: opt_string(row, "subscription_product"),
        account_identifier_hash: opt_string(row, "account_identifier_hash"),
        evidence_ref: row
            .get("evidence_ref")
            .map(|value| u16::try_from(value.as_u64().unwrap()).unwrap()),
        identity_parts: row
            .get("identity_parts")
            .map(|parts| parts.as_array().unwrap().iter().map(typed_part).collect()),
        cost_usd: opt_string(row, "cost_usd"),
        input_cost_usd: opt_string(row, "input_cost_usd"),
        output_cost_usd: opt_string(row, "output_cost_usd"),
        cache_read_cost_usd: opt_string(row, "cache_read_cost_usd"),
        cache_creation_cost_usd: opt_string(row, "cache_creation_cost_usd"),
    }
}

/// The fields `usage_accounting` and `attribution` read, typed from a W0 body.
fn typed_item(value: &Value) -> SnapshotItem {
    let mut item = valid_v6_batch_request().snapshots.remove(0);
    item.source_session_id = opt_string(value, "source_session_id").unwrap();
    item.input_tokens = count(value, "input_tokens");
    item.output_tokens = count(value, "output_tokens");
    item.cache_read_tokens = count(value, "cache_read_tokens");
    item.cache_creation_5m_tokens = count(value, "cache_creation_5m_tokens");
    item.cache_creation_1h_tokens = count(value, "cache_creation_1h_tokens");
    item.reasoning_output_tokens = count(value, "reasoning_output_tokens");
    item.unattributed_total_tokens = count(value, "unattributed_total_tokens");
    item.request_count = count(value, "request_count");
    item.usage_accounting_contract = opt_string(value, "usage_accounting_contract");
    item.model_usage = value["model_usage"]
        .as_array()
        .unwrap()
        .iter()
        .map(typed_row)
        .collect();
    item.usage_buckets = value["usage_buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|bucket| SnapshotUsageBucket {
            bucket_start: opt_string(bucket, "bucket_start").unwrap(),
            model_usage: bucket["model_usage"]
                .as_array()
                .unwrap()
                .iter()
                .map(typed_row)
                .collect(),
            first_activity_at: opt_string(bucket, "first_activity_at"),
            last_activity_at: opt_string(bucket, "last_activity_at"),
        })
        .collect();
    item.cost = value
        .get("cost")
        .filter(|cost| !cost.is_null())
        .map(|cost| SnapshotCost {
            total_cost_usd: opt_string(cost, "total_cost_usd"),
            input_cost_usd: opt_string(cost, "input_cost_usd"),
            output_cost_usd: opt_string(cost, "output_cost_usd"),
            cache_read_cost_usd: opt_string(cost, "cache_read_cost_usd"),
            cache_creation_cost_usd: opt_string(cost, "cache_creation_cost_usd"),
            evidence_source: opt_string(cost, "evidence_source").unwrap_or_default(),
        });
    item.provenance.collector = opt_string(&value["provenance"], "collector").unwrap();
    item.request_evidence = value
        .get("request_evidence")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| SnapshotRequestEvidence {
                    identity_basis: opt_string(entry, "identity_basis").unwrap(),
                    provider_workspace_hash: opt_string(entry, "provider_workspace_hash"),
                })
                .collect()
        })
        .unwrap_or_default();
    item.request_identity_refusals = count(value, "request_identity_refusals");
    item.origin = value
        .get("origin")
        .filter(|o| !o.is_null())
        .map(|origin| SnapshotOrigin {
            entrypoint: opt_string(origin, "entrypoint"),
            is_sidechain: origin.get("is_sidechain").and_then(Value::as_bool),
            used_workflow_orchestration: origin
                .get("used_workflow_orchestration")
                .and_then(Value::as_bool),
            ..SnapshotOrigin::default()
        });
    assert!(value
        .get("attribution_facts")
        .map_or(true, |facts| facts.is_null()
            || facts.as_array().unwrap().is_empty()));
    item.attribution_facts = Vec::new();
    item
}

#[test]
fn w0_r5_fixture_digest_reproduces() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(W0_DIR);
    let mut lines = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json") && name != "index.json")
        .map(|name| {
            let bytes = fs::read(dir.join(&name)).unwrap();
            format!("{name}\0{:x}", Sha256::digest(bytes))
        })
        .collect::<Vec<_>>();
    lines.sort();
    assert_eq!(lines.len(), 63);
    let digest = format!("{:x}", Sha256::digest(lines.join("\n").as_bytes()));
    let index = w0_index();
    assert_eq!(index["fixture_revision"], "session_identity_w0:r5");
    assert_eq!(index["canonicalization"], "session_identity_leaf:v3");
    assert_eq!(index["new_collector"], identity::COLLECTOR);
    assert_eq!(digest, index["fixture_digest"].as_str().unwrap());
    assert_eq!(
        digest,
        "2a9b46f12fcd0b23f063b3b845f4d1d64d235f5711877cd315575b92c7efd8e6"
    );
}

#[test]
fn w0_r5_bounds_match_daemon_caps() {
    let bounds = &w0_index()["bounds"];
    assert_eq!(
        bounds["evidence_entries"],
        identity::MAX_EVIDENCE_ENTRIES as u64
    );
    assert_eq!(
        bounds["authority_keys"],
        identity::MAX_AUTHORITY_KEYS as u64
    );
    assert_eq!(bounds["parts_per_row"], identity::MAX_PARTS_PER_ROW as u64);
    assert_eq!(bounds["total_parts"], identity::MAX_PARTS_PER_ITEM as u64);
    assert_eq!(bounds["bucket_rows"], identity::MAX_ROWS as u64);
    assert_eq!(bounds["top_level_rows"], identity::MAX_ROWS as u64);
    assert_eq!(bounds["item_bytes"], identity::MAX_ITEM_BYTES as u64);
    assert_eq!(bounds["money_max_usd"], "1000000000");
    assert_eq!(bounds["cost_fraction_digits"], 6);
}

/// The daemon's own component hashing reproduces W0 for every body: today's
/// bytes for old collectors, the identity leaf and coverage for the new one.
#[test]
fn w0_r5_usage_accounting_and_attribution_hash_parity() {
    let bodies = w0_bodies();
    assert_eq!(bodies.len(), 63);
    for (name, value, entry) in bodies {
        let item = typed_item(&value);
        let hashes = snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, &item);
        for component in ["usage_accounting", "attribution"] {
            assert_eq!(
                hashes[component],
                entry["component_hashes"][component].as_str().unwrap(),
                "{name} {component}"
            );
        }
        if let Some(expected) = entry.get("identity_leaf_sha256").and_then(Value::as_str) {
            let leaf = identity::semantic_leaf(&item);
            assert_eq!(sha256_hex(&[&leaf.to_string()]), expected, "{name} leaf");
            assert_eq!(leaf, entry["identity_leaf"], "{name} leaf body");
        } else if entry.get("identity_leaf").is_some() {
            assert!(entry["identity_leaf"].is_null(), "{name}");
            assert_ne!(item.provenance.collector, identity::COLLECTOR, "{name}");
        }
    }
}

/// Typed rows serialize to the exact W0 wire members (names, omission rules).
#[test]
fn w0_r5_wire_round_trip() {
    for (name, value, _) in w0_bodies() {
        let item = typed_item(&value);
        let rows = item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        );
        let wire_rows = value["model_usage"].as_array().unwrap().iter().chain(
            value["usage_buckets"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|bucket| bucket["model_usage"].as_array().unwrap()),
        );
        for (row, wire) in rows.zip(wire_rows) {
            let mut wire = wire.clone();
            let object = wire.as_object_mut().unwrap();
            for key in ["selector_context", "selector_sources"] {
                object.entry(key).or_insert(json!({}));
            }
            assert_eq!(serde_json::to_value(row).unwrap(), wire, "{name}");
        }
        let item_value = serde_json::to_value(&item).unwrap();
        assert_eq!(
            item_value.get("request_evidence"),
            value
                .get("request_evidence")
                .filter(|entries| !entries.as_array().unwrap().is_empty()),
            "{name}"
        );
        assert_eq!(
            item_value.get("request_identity_refusals"),
            value
                .get("request_identity_refusals")
                .filter(|refusals| refusals.as_u64() != Some(0)),
            "{name}"
        );
        if item.provenance.collector != identity::COLLECTOR {
            let text = serde_json::to_string(&item_value).unwrap();
            for key in [
                "evidence_ref",
                "identity_parts",
                "request_evidence",
                "request_identity_refusals",
            ] {
                assert!(!text.contains(key), "{name} old collector carries {key}");
            }
        }
    }
}

fn parse_usd_picos(text: &str) -> u128 {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    assert!(fraction.len() <= 12, "{text}");
    let fraction = format!("{fraction:0<12}");
    whole.parse::<u128>().unwrap() * USD_PICO_SCALE + fraction.parse::<u128>().unwrap()
}

fn canonical_money(item: &mut SnapshotItem) {
    let fix = |value: &mut Option<String>| {
        if let Some(text) = value {
            *text = usd_picos_string(parse_usd_picos(text));
        }
    };
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|b| b.model_usage.iter_mut()),
    ) {
        for value in [
            &mut row.cost_usd,
            &mut row.input_cost_usd,
            &mut row.output_cost_usd,
            &mut row.cache_read_cost_usd,
            &mut row.cache_creation_cost_usd,
        ] {
            fix(value);
        }
        for part in row.identity_parts.iter_mut().flatten() {
            for value in [
                &mut part.cost_usd,
                &mut part.input_cost_usd,
                &mut part.output_cost_usd,
                &mut part.cache_read_cost_usd,
                &mut part.cache_creation_cost_usd,
            ] {
                fix(value);
            }
        }
    }
}

fn basis_token(token: &str) -> Option<&'static str> {
    [
        identity::TELEMETRY,
        identity::TELEMETRY_LOGIN,
        identity::TRANSCRIPT_SOLE_LOGIN,
        identity::TRANSCRIPT_ORG,
        "transcript_email",
    ]
    .into_iter()
    .find(|basis| *basis == token)
}

fn holder_usage(holder: &SnapshotModelUsage, part: Option<&SnapshotIdentityPart>) -> UsageTotals {
    let money = |row: Option<&String>, part: Option<&String>| {
        part.or(row).map(|text| parse_usd_picos(text))
    };
    let (counts, costs) = match part {
        Some(part) => (
            [
                part.input_tokens,
                part.output_tokens,
                part.cache_read_tokens,
                part.cache_creation_5m_tokens,
                part.cache_creation_1h_tokens,
                part.reasoning_output_tokens,
                part.unattributed_total_tokens,
                part.request_count,
            ],
            [
                money(None, part.cost_usd.as_ref()),
                money(None, part.input_cost_usd.as_ref()),
                money(None, part.output_cost_usd.as_ref()),
                money(None, part.cache_read_cost_usd.as_ref()),
                money(None, part.cache_creation_cost_usd.as_ref()),
            ],
        ),
        None => (
            [
                holder.input_tokens,
                holder.output_tokens,
                holder.cache_read_tokens,
                holder.cache_creation_5m_tokens,
                holder.cache_creation_1h_tokens,
                holder.reasoning_output_tokens,
                holder.unattributed_total_tokens,
                holder.request_count,
            ],
            [
                money(holder.cost_usd.as_ref(), None),
                money(holder.input_cost_usd.as_ref(), None),
                money(holder.output_cost_usd.as_ref(), None),
                money(holder.cache_read_cost_usd.as_ref(), None),
                money(holder.cache_creation_cost_usd.as_ref(), None),
            ],
        ),
    };
    let reported = costs.iter().any(Option::is_some);
    UsageTotals {
        input_tokens: counts[0],
        output_tokens: counts[1],
        cache_read_tokens: counts[2],
        cache_creation_5m_tokens: counts[3],
        cache_creation_1h_tokens: counts[4],
        reasoning_output_tokens: counts[5],
        unattributed_total_tokens: counts[6],
        request_count: counts[7],
        costs: UsageCosts {
            observed: reported,
            reported,
            total: costs[0],
            input: costs[1],
            output: costs[2],
            cache_read: costs[3],
            cache_creation: costs[4],
        },
    }
}

/// Per-request contributions that reproduce a tagged W0 body's bucket rows.
fn contributions_of(item: &SnapshotItem) -> Option<Vec<Contribution>> {
    let untagged = if item.request_identity_refusals > 0 {
        RequestIdentity::Refused(Refusal::InvalidEvidence)
    } else {
        RequestIdentity::Missing
    };
    let key = |login: Option<&String>, evidence_ref: Option<u16>| -> Option<RequestIdentity> {
        let Some(evidence_ref) = evidence_ref else {
            return Some(untagged.clone());
        };
        let entry = &item.request_evidence[usize::from(evidence_ref)];
        Some(RequestIdentity::Tagged(AuthorityKey {
            login: login.cloned(),
            org: entry.provider_workspace_hash.clone(),
            basis: basis_token(&entry.identity_basis)?,
        }))
    };
    let mut out = Vec::new();
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let row_key = row_key_from_model_usage(row);
            match &row.identity_parts {
                Some(parts) => {
                    for part in parts {
                        out.push(Contribution {
                            bucket_start: bucket.bucket_start.clone(),
                            row_key: row_key.clone(),
                            usage: holder_usage(row, Some(part)),
                            identity: key(
                                part.account_identifier_hash.as_ref(),
                                part.evidence_ref,
                            )?,
                        });
                    }
                }
                None => out.push(Contribution {
                    bucket_start: bucket.bucket_start.clone(),
                    row_key,
                    usage: holder_usage(row, None),
                    identity: key(row.account_identifier_hash.as_ref(), row.evidence_ref)?,
                }),
            }
        }
    }
    Some(out)
}

fn stripped(item: &SnapshotItem) -> SnapshotItem {
    let mut today = item.clone();
    today.provenance.collector = "claude_code_jsonl".to_string();
    today.request_evidence.clear();
    today.request_identity_refusals = 0;
    for row in today.model_usage.iter_mut().chain(
        today
            .usage_buckets
            .iter_mut()
            .flat_map(|b| b.model_usage.iter_mut()),
    ) {
        row.account_identifier_hash = None;
        row.evidence_ref = None;
        row.identity_parts = None;
    }
    today
}

/// From per-request contributions, the builder emits each tagged W0 body:
/// identical rows/evidence for canonical bodies, an identical hash leaf for
/// the reordered ones (the server canonicalizes any order).
#[test]
fn w0_r5_builder_reproduces_tagged_bodies() {
    let mut checked = 0;
    for (name, value, _) in w0_bodies() {
        let mut expected = typed_item(&value);
        if expected.provenance.collector != identity::COLLECTOR
            || name.ends_with("-fallback")
            || name == "new-reported-unsplittable"
            || name == "new-marker-overflow"
        {
            continue;
        }
        canonical_money(&mut expected);
        let Some(contributions) = contributions_of(&expected) else {
            assert_eq!(
                name, "new-unknown-basis",
                "only the unknown token is unbuildable"
            );
            continue;
        };
        let mut built = stripped(&expected);
        let result =
            identity::apply(&mut built, &contributions).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(matches!(result, Tagged::Sent { .. }), "{name}: {result:?}");
        assert_eq!(
            built.request_identity_refusals > 0,
            expected.request_identity_refusals > 0,
            "{name}"
        );
        assert_eq!(
            identity::semantic_leaf(&built),
            identity::semantic_leaf(&expected),
            "{name}"
        );
        assert_eq!(
            snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, &built)["attribution"],
            snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, &expected)
                ["attribution"],
            "{name}"
        );
        let canonical = !name.contains("reordered")
            && !name.ends_with("-reversed")
            && !name.starts_with("p1-")
            && !name.ends_with("explicit-zero-refusals");
        if canonical {
            assert_eq!(built.request_evidence, expected.request_evidence, "{name}");
            assert_eq!(built.model_usage, expected.model_usage, "{name}");
            assert_eq!(built.usage_buckets, expected.usage_buckets, "{name}");
        }
        assert_eq!(
            built.snapshot_fingerprint,
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &built),
            "{name}"
        );
        checked += 1;
    }
    assert!(checked >= 40, "{checked}");
}

/// The cap rule emits W0's fallback shape: today's rows under the new
/// collector with refusals = bucket rows that lost identity (>= 1).
#[test]
fn w0_r5_cap_fallbacks_match_bodies() {
    for (tagged, fallback) in [
        ("new-cap-identities-16", "new-cap-identities-17-fallback"),
        ("new-cap-evidence-16", "new-cap-evidence-17-fallback"),
    ] {
        let bodies = w0_bodies();
        let find = |name: &str| typed_item(&bodies.iter().find(|(n, _, _)| n == name).unwrap().1);
        let mut expected = find(fallback);
        canonical_money(&mut expected);
        let mut base = find(tagged);
        canonical_money(&mut base);
        let mut contributions = contributions_of(&base).unwrap();
        // One more distinct authority key in the last bucket row.
        let mut extra = contributions.last().unwrap().clone();
        extra.identity = RequestIdentity::Tagged(AuthorityKey {
            login: Some("f".repeat(64)),
            org: Some("e".repeat(64)),
            basis: identity::TELEMETRY,
        });
        contributions.push(extra);
        let mut built = stripped(&base);
        let added = contributions.last().unwrap().usage.clone();
        let target = &mut built.usage_buckets.last_mut().unwrap().model_usage[0];
        let grow = |row: &mut SnapshotModelUsage| {
            row.input_tokens += added.input_tokens;
            row.output_tokens += added.output_tokens;
            row.request_count += added.request_count;
            row.cost_usd = Some(usd_picos_string(
                parse_usd_picos(row.cost_usd.as_ref().unwrap()) + added.costs.total.unwrap(),
            ));
        };
        grow(target);
        grow(&mut built.model_usage[0]);
        let result = identity::apply(&mut built, &contributions).unwrap();
        let Tagged::Fallback { refusals, .. } = result else {
            panic!("{tagged}: {result:?}")
        };
        assert_eq!(refusals, expected.request_identity_refusals, "{fallback}");
        assert_eq!(built.provenance.collector, identity::COLLECTOR);
        assert!(built.request_evidence.is_empty());
        assert!(built
            .model_usage
            .iter()
            .chain(built.usage_buckets.iter().flat_map(|b| &b.model_usage))
            .all(|row| row.identity_parts.is_none()
                && row.evidence_ref.is_none()
                && row.account_identifier_hash.is_none()));
        assert_eq!(identity::semantic_leaf(&built)["refused"], true);
    }
}

fn one_row_item(rows: &[(u64, Option<&str>)]) -> SnapshotItem {
    let mut item = valid_v6_batch_request().snapshots.remove(0);
    let mut row = typed_row(
        &json!({"model": "claude-haiku-4-5", "input_tokens": 0, "output_tokens": 0,
        "cache_read_tokens": 0, "cache_creation_5m_tokens": 0, "cache_creation_1h_tokens": 0,
        "reasoning_output_tokens": 0, "request_count": 0}),
    );
    let mut cost = 0_u128;
    let mut any_cost = false;
    for (tokens, money) in rows {
        row.input_tokens += tokens;
        row.request_count += 1;
        if let Some(money) = money {
            cost += parse_usd_picos(money);
            any_cost = true;
        }
    }
    row.cost_usd = any_cost.then(|| usd_picos_string(cost));
    item.provenance.collector = "claude_code_jsonl".to_string();
    item.model_usage = vec![row.clone()];
    item.usage_buckets = vec![SnapshotUsageBucket {
        bucket_start: "2026-09-01T10:00:00Z".to_string(),
        model_usage: vec![row],
        first_activity_at: None,
        last_activity_at: None,
    }];
    item
}

fn contribution(
    item: &SnapshotItem,
    tokens: u64,
    money: Option<&str>,
    identity: RequestIdentity,
) -> Contribution {
    let mut row = item.usage_buckets[0].model_usage[0].clone();
    row.input_tokens = tokens;
    row.request_count = 1;
    row.cost_usd = money.map(str::to_string);
    Contribution {
        bucket_start: item.usage_buckets[0].bucket_start.clone(),
        row_key: row_key_from_model_usage(&item.usage_buckets[0].model_usage[0]),
        usage: holder_usage(&row, None),
        identity,
    }
}

fn telemetry(login: char, org: char) -> RequestIdentity {
    RequestIdentity::Tagged(AuthorityKey {
        login: Some(login.to_string().repeat(64)),
        org: Some(org.to_string().repeat(64)),
        basis: identity::TELEMETRY,
    })
}

#[test]
fn builder_refuses_rows_it_cannot_reproduce_and_leaves_them_untouched() {
    let item = one_row_item(&[(10, None), (20, None)]);
    let mut changed = item.clone();
    let wrong = vec![contribution(&item, 10, None, telemetry('a', 'd'))];
    assert_eq!(
        identity::apply(&mut changed, &wrong),
        Err(identity::Ineligible::RowsNotReproduced)
    );
    assert_eq!(
        serde_json::to_value(&changed).unwrap(),
        serde_json::to_value(&item).unwrap()
    );
}

#[test]
fn builder_never_emits_money_beyond_micro_dollars() {
    let item = one_row_item(&[(10, Some("0.0000001")), (20, Some("1"))]);
    let mut changed = item.clone();
    let contributions = vec![
        contribution(&item, 10, Some("0.0000001"), telemetry('a', 'd')),
        contribution(&item, 20, Some("1"), telemetry('b', 'd')),
    ];
    assert_eq!(
        identity::apply(&mut changed, &contributions),
        Err(identity::Ineligible::MoneyNotMicroExact)
    );
    assert_eq!(changed.provenance.collector, "claude_code_jsonl");
}

#[test]
fn builder_keeps_unsplittable_reported_money_untagged_and_refused() {
    // Today's row folds only observed money: $1 from one request while the
    // other request has none. That total cannot be split per request.
    let mut item = one_row_item(&[(10, Some("1")), (20, None)]);
    let contributions = vec![
        contribution(&item, 10, Some("1"), telemetry('a', 'd')),
        contribution(&item, 20, None, telemetry('b', 'd')),
    ];
    let result = identity::apply(&mut item, &contributions).unwrap();
    assert_eq!(result, Tagged::Sent { refusals: 1 });
    let row = &item.usage_buckets[0].model_usage[0];
    assert!(row.identity_parts.is_none() && row.evidence_ref.is_none());
    assert_eq!(row.cost_usd.as_deref(), Some("1"));
    assert!(item.request_evidence.is_empty());
    // A row total that is not today's fold of the requests is not reproduced.
    let mut wrong = one_row_item(&[(10, Some("1")), (20, Some("2"))]);
    let contributions = vec![
        contribution(&wrong, 10, Some("1"), telemetry('a', 'd')),
        contribution(&wrong, 20, None, telemetry('b', 'd')),
    ];
    assert_eq!(
        identity::apply(&mut wrong, &contributions),
        Err(identity::Ineligible::RowsNotReproduced)
    );
}

#[test]
fn builder_hash_is_order_free_and_moves_with_the_login() {
    let item = one_row_item(&[(10, Some("1")), (20, Some("2"))]);
    let forward = vec![
        contribution(&item, 10, Some("1"), telemetry('a', 'd')),
        contribution(&item, 20, Some("2"), telemetry('b', 'e')),
    ];
    let mut reverse = forward.clone();
    reverse.reverse();
    let (mut one, mut two) = (item.clone(), item.clone());
    identity::apply(&mut one, &forward).unwrap();
    identity::apply(&mut two, &reverse).unwrap();
    assert_eq!(
        serde_json::to_vec(&one).unwrap(),
        serde_json::to_vec(&two).unwrap()
    );
    let mut swapped = forward.clone();
    swapped[0].identity = telemetry('c', 'd');
    let mut three = item.clone();
    identity::apply(&mut three, &swapped).unwrap();
    let hash = |item: &SnapshotItem| {
        snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, item)["usage_accounting"]
            .clone()
    };
    assert_ne!(hash(&one), hash(&three), "the per-row login is hashed");
    assert_eq!(
        one.request_evidence, three.request_evidence,
        "evidence is org+basis only"
    );
}

#[test]
fn builder_enforces_the_declared_parts_per_item_cap() {
    // 100 bucket rows x 2 hours of 11 parts each = 2,200 bucket parts plus top
    // rows: over the 2,048 declared bound, so the stateless fallback applies.
    let mut item = valid_v6_batch_request().snapshots.remove(0);
    item.provenance.collector = "claude_code_jsonl".to_string();
    let mut contributions = Vec::new();
    let mut top = Vec::new();
    let mut buckets = Vec::new();
    for hour in 0..2 {
        let mut rows = Vec::new();
        for model in 0..100 {
            let mut row = typed_row(&json!({"model": format!("claude-model-{model:03}"),
                "input_tokens": 11, "output_tokens": 0, "cache_read_tokens": 0,
                "cache_creation_5m_tokens": 0, "cache_creation_1h_tokens": 0,
                "reasoning_output_tokens": 0, "request_count": 11}));
            row.selector_context.clear();
            let bucket_start = format!("2026-09-01T1{hour}:00:00Z");
            for login in 0..11_u8 {
                let mut one = row.clone();
                one.input_tokens = 1;
                one.request_count = 1;
                contributions.push(Contribution {
                    bucket_start: bucket_start.clone(),
                    row_key: row_key_from_model_usage(&row),
                    usage: holder_usage(&one, None),
                    identity: telemetry(char::from(b'a' + login), 'd'),
                });
            }
            rows.push(row);
        }
        buckets.push(SnapshotUsageBucket {
            bucket_start: format!("2026-09-01T1{hour}:00:00Z"),
            model_usage: rows.clone(),
            first_activity_at: None,
            last_activity_at: None,
        });
        top = rows;
    }
    for row in &mut top {
        row.input_tokens *= 2;
        row.request_count *= 2;
    }
    item.model_usage = top;
    item.usage_buckets = buckets;
    let result = identity::apply(&mut item, &contributions).unwrap();
    let Tagged::Fallback { over_cap, refusals } = result else {
        panic!("{result:?}")
    };
    assert!(
        over_cap.contains(&identity::OverCap::PartsPerItem),
        "{over_cap:?}"
    );
    assert_eq!(refusals, 200);
    assert!(identity::item_bytes(&item) <= identity::MAX_ITEM_BYTES);
}

// --- Classification ---------------------------------------------------------

const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";

fn org_identity(org: &str) -> crate::claude_local_otel::ClaudeRequestIdentityEvidence {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
    };
    crate::claude_local_otel::ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "provider-sha256:v1".to_string(),
        disposition: ClaudeIdentityDisposition::Complete,
        account: ClaudeIdentityAttributeEvidence {
            disposition: ClaudeIdentityDisposition::Complete,
            origin: ClaudeIdentityAttributeOrigin::LogRecord,
            log_record_hash: Some("a".repeat(64)),
            resource_hash: None,
        },
        organization: ClaudeIdentityAttributeEvidence {
            disposition: ClaudeIdentityDisposition::Complete,
            origin: ClaudeIdentityAttributeOrigin::LogRecord,
            log_record_hash: Some(org.to_string()),
            resource_hash: None,
        },
    }
}

fn reports(
    api: Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>,
    trace: Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>,
) -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let mut api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    api_report.evidence.insert(ROOT.to_string(), api);
    let mut trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    trace_report.evidence.insert(ROOT.to_string(), trace);
    (api_report, trace_report)
}

fn signed(
    mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    row.fingerprint.clear();
    let bytes = serde_json::to_vec(&row).unwrap();
    row.fingerprint = format!("sha256:{:x}", Sha256::digest(bytes));
    row
}

fn facts<'a>(request_id: &'a str, at: Option<u64>, marker: MarkerVerdict) -> RequestFacts<'a> {
    RequestFacts {
        root: ROOT,
        source_session_id: ROOT,
        request_id,
        terminal_unix_seconds: at,
        event_clock_complete: true,
        marker,
        desktop: false,
        scan_unix_seconds: Some(1_000_000),
    }
}

fn healthy() -> BTreeSet<String> {
    BTreeSet::from([ROOT.to_string()])
}

#[test]
fn classify_follows_the_session_rulings() {
    let org_d = "d".repeat(64);
    let org_e = "e".repeat(64);
    let mut with_org = complete_api_row(ROOT, "req_org", 1, 10, 1, 0);
    with_org.request_identity = Some(org_identity(&org_d));
    let with_org = signed(with_org);
    let login_only = complete_api_row(ROOT, "req_login", 2, 10, 1, 0);
    let mut bad_org = complete_api_row(ROOT, "req_bad_org", 3, 10, 1, 0);
    let mut contradictory = org_identity(&org_d);
    contradictory.organization.disposition =
        crate::claude_local_otel::ClaudeIdentityDisposition::Conflict;
    bad_org.request_identity = Some(contradictory);
    let bad_org = signed(bad_org);
    let dup = complete_api_row(ROOT, "req_dup", 4, 10, 1, 0);
    let trace = ["req_org", "req_login", "req_bad_org", "req_dup"]
        .into_iter()
        .map(|id| complete_trace_row(ROOT, id, ""))
        .collect::<Vec<_>>();
    let (api, trace) = reports(vec![with_org, login_only, bad_org, dup.clone(), dup], trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), healthy(), None);
    let at = Some(900_000);
    let login = Some("a".repeat(64));
    assert_eq!(
        identity::classify(&evidence, &facts("req_org", at, MarkerVerdict::None)),
        RequestIdentity::Tagged(AuthorityKey {
            login: login.clone(),
            org: Some(org_d.clone()),
            basis: identity::TELEMETRY
        })
    );
    // A supplied contradictory org is never dropped to obtain login-only.
    assert_eq!(
        identity::classify(&evidence, &facts("req_bad_org", at, MarkerVerdict::None)),
        RequestIdentity::Refused(Refusal::ContradictoryOrg)
    );
    assert_eq!(
        identity::classify(&evidence, &facts("req_dup", at, MarkerVerdict::None)),
        RequestIdentity::Refused(Refusal::ConflictingDuplicate)
    );
    // Login-only telemetry joins a trusted marker org only when complete
    // telemetry already pairs that login with it.
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_login", at, MarkerVerdict::Trusted(org_d.clone()))
        ),
        RequestIdentity::Tagged(AuthorityKey {
            login: login.clone(),
            org: Some(org_d.clone()),
            basis: identity::TELEMETRY_LOGIN
        })
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_login", at, MarkerVerdict::Trusted(org_e.clone()))
        ),
        RequestIdentity::Tagged(AuthorityKey {
            login: login.clone(),
            org: None,
            basis: identity::TELEMETRY_LOGIN
        })
    );
    // Original clock is required for any tag.
    let mut no_clock = facts("req_org", None, MarkerVerdict::None);
    no_clock.event_clock_complete = false;
    assert_eq!(
        identity::classify(&evidence, &no_clock),
        RequestIdentity::Refused(Refusal::BadClock)
    );

    // No telemetry row: pending only for this request's own young clock with
    // a healthy writer; otherwise missing and open to transcript evidence.
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_new", Some(999_900), MarkerVerdict::None)
        ),
        RequestIdentity::Refused(Refusal::Pending)
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_old", Some(999_000), MarkerVerdict::None)
        ),
        RequestIdentity::Missing
    );
    let unhealthy_writer = ScanEvidence::new(&api, &trace, BTreeSet::new(), BTreeSet::new(), None);
    assert_eq!(
        identity::classify(
            &unhealthy_writer,
            &facts("req_new", Some(999_900), MarkerVerdict::None)
        ),
        RequestIdentity::Missing
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts(
                "req_old",
                Some(999_000),
                MarkerVerdict::Trusted(org_e.clone())
            )
        ),
        RequestIdentity::Tagged(AuthorityKey {
            login: None,
            org: Some(org_e.clone()),
            basis: identity::TRANSCRIPT_ORG
        })
    );
    for (verdict, refusal) in [
        (MarkerVerdict::Overflow, Refusal::MarkerOverflow),
        (MarkerVerdict::UntrustedFlip, Refusal::UntrustedFlip),
        (MarkerVerdict::BadOrg, Refusal::ContradictoryOrg),
    ] {
        assert_eq!(
            identity::classify(&evidence, &facts("req_old", Some(999_000), verdict)),
            RequestIdentity::Refused(refusal)
        );
    }
    // Unreadable stronger evidence never falls through to transcript bases.
    let unreadable = ScanEvidence::new(&api, &trace, healthy(), BTreeSet::new(), None);
    assert_eq!(
        identity::classify(
            &unreadable,
            &facts("req_old", Some(999_000), MarkerVerdict::Trusted(org_e))
        ),
        RequestIdentity::Refused(Refusal::IncompleteEvidence)
    );
}

#[test]
fn classify_sole_login_needs_desktop_and_a_census_after_the_request() {
    let org = "d".repeat(64);
    let (api, trace) = reports(Vec::new(), Vec::new());
    let census = |at: u64, logins: &[&str]| DesktopCensus {
        completed_at_unix_seconds: at,
        logins_by_org: BTreeMap::from([(
            org.clone(),
            logins.iter().map(|login| login.to_string()).collect(),
        )]),
    };
    let desktop = |evidence: &ScanEvidence<'_>, desktop: bool| {
        let mut request = facts(
            "req_old",
            Some(999_000),
            MarkerVerdict::Trusted(org.clone()),
        );
        request.desktop = desktop;
        identity::classify(evidence, &request)
    };
    let sole = RequestIdentity::Tagged(AuthorityKey {
        login: Some(LOGIN_A.to_string()),
        org: Some(org.clone()),
        basis: identity::TRANSCRIPT_SOLE_LOGIN,
    });
    let org_only = RequestIdentity::Tagged(AuthorityKey {
        login: None,
        org: Some(org.clone()),
        basis: identity::TRANSCRIPT_ORG,
    });
    let fresh = ScanEvidence::new(
        &api,
        &trace,
        BTreeSet::new(),
        BTreeSet::new(),
        Some(census(999_500, &[LOGIN_A])),
    );
    assert_eq!(desktop(&fresh, true), sole);
    assert_eq!(
        desktop(&fresh, false),
        org_only,
        "terminal sole-login waits for Phase 2"
    );
    let stale = ScanEvidence::new(
        &api,
        &trace,
        BTreeSet::new(),
        BTreeSet::new(),
        Some(census(998_000, &[LOGIN_A])),
    );
    assert_eq!(
        desktop(&stale, true),
        org_only,
        "census older than the request"
    );
    let two = ScanEvidence::new(
        &api,
        &trace,
        BTreeSet::new(),
        BTreeSet::new(),
        Some(census(999_500, &[LOGIN_A, "b"])),
    );
    assert_eq!(desktop(&two, true), org_only);
    let none = ScanEvidence::new(&api, &trace, BTreeSet::new(), BTreeSet::new(), None);
    assert_eq!(desktop(&none, true), org_only);
}

#[test]
fn desktop_census_witness_is_bound_to_completion_process_and_inventory() {
    let mut index = ScanIndex::default();
    assert_eq!(
        identity::desktop_census_at(&index, 100),
        None,
        "unknown for old indexes"
    );
    let dirs = BTreeSet::from([PathBuf::from("/synthetic/store")]);
    index.claude_desktop_identity_census_complete = true;
    index.claude_desktop_census_witness = Some(identity::DesktopCensusWitness::new(50, &dirs));
    index.claude_desktop_title_files.insert(
        "a".to_string(),
        ClaudeDesktopTitleIndexEntry {
            cli_session_id: "s1".to_string(),
            title: None,
            user_set: false,
            account_identifier_hash: None,
            original_identity: Some(ClaudeDesktopIdentityEvidence {
                account_identifier_hash: Some(LOGIN_A.to_string()),
                provider_workspace_hash: Some("d".repeat(64)),
                source_created_at: None,
                imported: false,
            }),
        },
    );
    index.claude_desktop_title_files.insert(
        "b".to_string(),
        ClaudeDesktopTitleIndexEntry {
            cli_session_id: "s2".to_string(),
            title: None,
            user_set: false,
            account_identifier_hash: None,
            original_identity: Some(ClaudeDesktopIdentityEvidence {
                account_identifier_hash: Some("b".repeat(64)),
                provider_workspace_hash: Some("d".repeat(64)),
                source_created_at: None,
                imported: true,
            }),
        },
    );
    let census = identity::desktop_census_at(&index, 100).unwrap();
    assert_eq!(census.completed_at_unix_seconds, 50);
    assert_eq!(
        census.logins_by_org["d".repeat(64).as_str()].len(),
        1,
        "imported identity ignored"
    );
    assert_eq!(
        identity::desktop_census_at(&index, 49),
        None,
        "clock before completion"
    );
    let mut moved = index.clone();
    identity::DesktopCensusWitness::retain_for_inventory(
        &mut moved.claude_desktop_census_witness,
        &BTreeSet::from([PathBuf::from("/synthetic/other")]),
    );
    assert_eq!(
        identity::desktop_census_at(&moved, 100),
        None,
        "inventory changed"
    );
    let mut incomplete = index.clone();
    incomplete.claude_desktop_identity_census_complete = false;
    assert_eq!(identity::desktop_census_at(&incomplete, 100), None);
    let restored: ScanIndex =
        serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap();
    assert_eq!(
        restored.claude_desktop_census_witness,
        index.claude_desktop_census_witness
    );
    let mut old: Value = serde_json::to_value(&index).unwrap();
    old.as_object_mut()
        .unwrap()
        .remove("claude_desktop_census_witness");
    let old: ScanIndex = serde_json::from_value(old).unwrap();
    assert_eq!(old.claude_desktop_census_witness, None);
}

// --- Markers ----------------------------------------------------------------

fn marker(org: &str) -> Value {
    json!({"type": "attachment", "attachment": {"type": "credential_org", "organizationUuid": org}})
}

fn context(email: &str) -> Value {
    json!({"type": "attachment", "attachment": {"type": "session_context", "context": {"userEmail": email}}})
}

const ORG_1: &str = "11111111-1111-4111-8111-111111111111";
const ORG_2: &str = "22222222-2222-4222-8222-222222222222";

fn org_hash(uuid: &str) -> String {
    ottto_core::billing_identity_hash(
        "anthropic",
        "organization",
        &crate::claude_local_otel::canonical_uuid(uuid).unwrap(),
    )
    .unwrap()
}

#[test]
fn markers_govern_later_responses_and_distrust_unexplained_flips() {
    let mut markers = None;
    identity::note_marker_line(&mut markers, &context("one@example.invalid"), 0);
    identity::note_marker_line(&mut markers, &marker(ORG_1), 0);
    identity::note_marker_line(&mut markers, &marker(ORG_2), 3);
    identity::note_marker_line(&mut markers, &context("two@example.invalid"), 5);
    identity::note_marker_line(&mut markers, &marker(ORG_1), 5);
    let markers = markers.unwrap();
    assert_eq!(
        markers.verdict(0, false),
        MarkerVerdict::Trusted(org_hash(ORG_1))
    );
    assert_eq!(
        markers.verdict(2, false),
        MarkerVerdict::Trusted(org_hash(ORG_1))
    );
    assert_eq!(markers.verdict(3, false), MarkerVerdict::UntrustedFlip);
    assert_eq!(
        markers.verdict(3, true),
        MarkerVerdict::Trusted(org_hash(ORG_2)),
        "Desktop markers are trusted"
    );
    assert_eq!(
        markers.verdict(9, false),
        MarkerVerdict::Trusted(org_hash(ORG_1)),
        "flip with a new context"
    );
    let mut none = None;
    identity::note_marker_line(&mut none, &json!({"type": "assistant"}), 0);
    assert!(none.is_none(), "no state without a marker line");
    let mut bad = None;
    identity::note_marker_line(&mut bad, &marker("not-a-uuid"), 0);
    assert_eq!(bad.unwrap().verdict(0, false), MarkerVerdict::BadOrg);
    let mut many = None;
    for position in 0..=identity::MAX_ORG_MARKERS_PER_FILE as u64 {
        identity::note_marker_line(&mut many, &marker(ORG_1), position);
    }
    let many = many.unwrap();
    assert_eq!(many.verdict(0, false), MarkerVerdict::Overflow);
    if crate::heap_layout_bound::layout_supported() {
        assert_eq!(
            crate::heap_layout_bound::completed_bound(&many, usize::MAX).map(|bytes| bytes < 4096),
            Some(true),
            "overflow releases entries"
        );
    }
}

#[test]
fn parser_captures_owned_markers_and_never_inherited_ones() {
    let dir = temp_dir("claude-request-identity-markers");
    let path = dir.join(format!("{ROOT}.jsonl"));
    let lines = [
        json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment", "sessionId": ROOT,
            "attachment": {"type": "credential_org", "organizationUuid": ORG_1}}),
        json!({"timestamp": "2026-08-02T07:00:01Z", "type": "assistant", "sessionId": ROOT, "requestId": "req_1",
            "message": {"id": "m1", "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 1}}}),
    ];
    fs::write(
        &path,
        lines
            .iter()
            .map(|line| line.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let items = parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", "fp".into()).unwrap();
    let markers = items[0].claude_org_markers.as_deref().unwrap();
    let sequence = items[0].claude_usage_occurrences["req_1"].sequence;
    assert_eq!(
        markers.verdict(sequence, false),
        MarkerVerdict::Trusted(org_hash(ORG_1))
    );
    assert!(!serde_json::to_string(&items[0])
        .unwrap()
        .contains("credential_org"));
    let _ = fs::remove_dir_all(dir);
}

// --- End to end on both usage paths -------------------------------------------

#[test]
fn transcript_path_tags_parsed_requests_from_their_own_telemetry() {
    let (dir, root, mut items) = claude_account_family_fixture();
    items.truncate(1);
    let api = (1..=4)
        .map(|n| {
            let mut row = complete_api_row(&root, &format!("req_{n}"), n, 10, 10, 0);
            if n > 2 {
                row.account_identifier_hash = Some("b".repeat(64));
            }
            signed(row)
        })
        .collect::<Vec<_>>();
    let trace = (1..=4)
        .map(|n| complete_trace_row(&root, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    let (api, trace) = reports(api, trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), healthy(), None);
    let before = items[0].clone();
    let outcome = identity::apply_scan(&mut items, &evidence, &BTreeMap::new());
    assert_eq!(
        outcome,
        identity::ScanOutcome {
            sent: 1,
            ..Default::default()
        }
    );
    let item = &items[0];
    assert_eq!(item.provenance.collector, identity::COLLECTOR);
    // Unchanged usage grain and totals.
    assert_eq!(item.input_tokens, before.input_tokens);
    assert_eq!(item.usage_buckets.len(), before.usage_buckets.len());
    let row = &item.usage_buckets[0].model_usage[0];
    let parts = row.identity_parts.as_ref().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts.iter().map(|p| p.request_count).sum::<u64>(),
        row.request_count
    );
    assert_eq!(item.request_evidence.len(), 1);
    assert_eq!(
        item.request_evidence[0].identity_basis,
        identity::TELEMETRY_LOGIN
    );
    assert_eq!(item.request_identity_refusals, 0);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reported_path_tags_from_recorded_placements() {
    let (dir, root, mut items) = claude_account_family_fixture();
    items.truncate(1);
    let item = &items[0];
    let mut placements = Vec::new();
    let mut api = Vec::new();
    let mut bucket_rows: BTreeMap<RowKey, UsageTotals> = BTreeMap::new();
    for (request_id, occurrence) in &item.claude_usage_occurrences {
        let (row_key, _, _) = build_row_identity(
            occurrence.model.as_deref().unwrap(),
            &occurrence.selector,
            occurrence.reasoning_effort.as_deref(),
        );
        let mut usage = occurrence.usage.clone();
        usage.request_count = 1;
        usage.costs = UsageCosts {
            observed: true,
            reported: true,
            total: Some(100_000_000),
            ..Default::default()
        };
        bucket_rows.entry(row_key.clone()).or_default().add(&usage);
        placements.push(identity::Placement {
            request_id: request_id.clone(),
            bucket_start: "2026-08-02T07:00:00Z".to_string(),
            row_key,
            usage,
            occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
            timestamp: occurrence.timestamp.clone().unwrap(),
        });
        let n: u64 = request_id.trim_start_matches("req_").parse().unwrap();
        let mut row = complete_api_row(&root, request_id, n, 10, 10, 0);
        if n % 2 == 0 {
            row.account_identifier_hash = Some("b".repeat(64));
        }
        api.push(signed(row));
    }
    let trace = api
        .iter()
        .map(|row| complete_trace_row(&root, &row.request_id, ""))
        .collect::<Vec<_>>();
    let mut item = items.remove(0);
    item.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".to_string());
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|b| b.model_usage.iter_mut()),
    ) {
        row.cost_usd = Some(usd_picos_string(
            100_000_000 * u128::from(row.request_count),
        ));
    }
    let (api, trace) = reports(api, trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), healthy(), None);
    let placements = BTreeMap::from([(item.source_session_id.clone(), placements)]);
    let mut items = vec![item];
    let outcome = identity::apply_scan(&mut items, &evidence, &placements);
    assert_eq!(outcome.sent, 1, "{outcome:?}");
    let parts = items[0].usage_buckets[0].model_usage[0]
        .identity_parts
        .clone()
        .unwrap();
    assert_eq!(parts.len(), 2);
    assert!(parts
        .iter()
        .all(|part| part.cost_usd == Some("0.0002".to_string())));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unreadable_sidecars_refuse_and_unqualified_items_keep_todays_bytes() {
    let (dir, _root, items) = claude_account_family_fixture();
    let (api, trace) = reports(Vec::new(), Vec::new());
    let unreadable = ScanEvidence::new(&api, &trace, healthy(), BTreeSet::new(), None);
    let mut refused = items.clone();
    let outcome = identity::apply_scan(&mut refused, &unreadable, &BTreeMap::new());
    assert_eq!(
        outcome,
        identity::ScanOutcome {
            sent: 2,
            ..Default::default()
        }
    );
    for item in &refused {
        assert_eq!(item.provenance.collector, identity::COLLECTOR);
        let rows = item
            .usage_buckets
            .iter()
            .map(|b| b.model_usage.len() as u64)
            .sum::<u64>();
        assert_eq!(item.request_identity_refusals, rows);
        assert!(item.request_evidence.is_empty());
        assert_eq!(identity::semantic_leaf(item)["refused"], true);
    }
    let mut unqualified = items.clone();
    for item in &mut unqualified {
        item.claude_context_curve_request_index_complete = false;
    }
    let before = serde_json::to_vec(&unqualified).unwrap();
    let outcome = identity::apply_scan(&mut unqualified, &unreadable, &BTreeMap::new());
    assert_eq!(
        outcome,
        identity::ScanOutcome {
            ineligible: 2,
            ..Default::default()
        }
    );
    assert_eq!(serde_json::to_vec(&unqualified).unwrap(), before);
    let _ = fs::remove_dir_all(dir);
}

/// Equal-input resource observation (synthetic, bounded): one 2,000-response
/// transcript over 10 hours with 2 logins and 64 marker lines. Emission is off
/// in released builds, so production pays none of this; these are the costs a
/// later flip would add on the same input.
#[test]
fn equal_input_resource_observation() {
    let dir = temp_dir("claude-request-identity-resources");
    let path = dir.join(format!("{ROOT}.jsonl"));
    let mut text = String::new();
    let mut lines = Vec::new();
    for n in 0..2_000_u64 {
        if n % 32 == 0 {
            let org = if (n / 32) % 2 == 0 { ORG_1 } else { ORG_2 };
            lines.push(json!({"timestamp": format!("2026-08-02T{:02}:00:00Z", n / 200), "type": "attachment",
                "sessionId": ROOT, "attachment": {"type": "credential_org", "organizationUuid": org}}));
        }
        lines.push(json!({"timestamp": format!("2026-08-02T{:02}:{:02}:{:02}Z", n / 200, (n % 200) / 4, n % 60),
            "type": "assistant", "sessionId": ROOT, "requestId": format!("req_{n}"),
            "message": {"id": format!("m{n}"), "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10 + n % 7, "output_tokens": 1}}}));
    }
    for line in &lines {
        text.push_str(&line.to_string());
        text.push('\n');
    }
    fs::write(&path, &text).unwrap();
    let started = std::time::Instant::now();
    let mut markers = None;
    for (position, line) in lines.iter().enumerate() {
        identity::note_marker_line(&mut markers, line, position as u64);
    }
    let capture_ns = started.elapsed().as_nanos();
    // Layout accounting is optional on unvalidated toolchains; 0 = unmeasured.
    let marker_heap =
        crate::heap_layout_bound::completed_bound(markers.as_ref().unwrap(), usize::MAX)
            .unwrap_or(0);
    let started = std::time::Instant::now();
    let mut items =
        parse_claude_code_jsonl_file(&path, "2026-08-02T11:00:00Z", "fp".into()).unwrap();
    let parse_ns = started.elapsed().as_nanos();
    assert_eq!(items[0].request_count, 2_000);
    let api = (0..2_000_u64)
        .map(|n| {
            let mut row = complete_api_row(ROOT, &format!("req_{n}"), n % 60, 10 + n % 7, 1, 0);
            if n % 2 == 1 {
                row.account_identifier_hash = Some("b".repeat(64));
            }
            signed(row)
        })
        .collect::<Vec<_>>();
    let trace = (0..2_000_u64)
        .map(|n| complete_trace_row(ROOT, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    let (api, trace) = reports(api, trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), healthy(), None);
    let old_bytes = identity::item_bytes(&items[0]);
    let started = std::time::Instant::now();
    let outcome = identity::apply_scan(&mut items, &evidence, &BTreeMap::new());
    let tag_ns = started.elapsed().as_nanos();
    let new_bytes = identity::item_bytes(&items[0]);
    eprintln!(
        "request identity resources: lines={} capture_ns={capture_ns} parse_ns={parse_ns} \
         marker_heap_bytes={marker_heap} tag_ns={tag_ns} item_bytes_old={old_bytes} \
         item_bytes_new={new_bytes} buckets={} outcome={outcome:?} \
         size_delta_item={} size_delta_index_witness={}",
        lines.len(),
        items[0].usage_buckets.len(),
        std::mem::size_of::<Option<Box<identity::OrgMarkers>>>(),
        std::mem::size_of::<Option<identity::DesktopCensusWitness>>(),
    );
    assert_eq!(outcome.sent, 1);
    assert!(marker_heap < 16 * 1024, "{marker_heap}");
    assert!(new_bytes <= identity::MAX_ITEM_BYTES);
    assert_eq!(items[0].request_count, 2_000, "count conservation");
    let _ = fs::remove_dir_all(dir);
}

// --- Review regressions ---------------------------------------------------------

#[test]
fn transcript_bases_need_the_original_clock() {
    let (api, trace) = reports(Vec::new(), Vec::new());
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), BTreeSet::new(), None);
    let mut carried = facts(
        "req_old",
        Some(999_000),
        MarkerVerdict::Trusted("d".repeat(64)),
    );
    carried.event_clock_complete = false;
    assert_eq!(
        identity::classify(&evidence, &carried),
        RequestIdentity::Refused(Refusal::BadClock)
    );
    let unstamped = facts("req_old", None, MarkerVerdict::Trusted("d".repeat(64)));
    assert_eq!(
        identity::classify(&evidence, &unstamped),
        RequestIdentity::Refused(Refusal::BadClock)
    );
    // Without any transcript evidence the request is simply missing.
    let mut plain = facts("req_old", None, MarkerVerdict::None);
    plain.event_clock_complete = false;
    assert_eq!(identity::classify(&evidence, &plain), RequestIdentity::Missing);
}

#[test]
fn only_intact_rows_establish_login_org_membership() {
    let org = "d".repeat(64);
    let mut forged = complete_api_row(ROOT, "req_forged", 1, 10, 1, 0);
    forged.request_identity = Some(org_identity(&org));
    // Not re-signed: its fingerprint no longer matches its content.
    let login_only = complete_api_row(ROOT, "req_login", 2, 10, 1, 0);
    let (api, trace) = reports(
        vec![forged, login_only],
        vec![
            complete_trace_row(ROOT, "req_forged", ""),
            complete_trace_row(ROOT, "req_login", ""),
        ],
    );
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), healthy(), None);
    assert!(evidence.memberships.is_empty());
    assert_eq!(
        identity::classify(&evidence, &facts("req_forged", Some(900_000), MarkerVerdict::None)),
        RequestIdentity::Refused(Refusal::InvalidEvidence)
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_login", Some(900_000), MarkerVerdict::Trusted(org))
        ),
        RequestIdentity::Tagged(AuthorityKey {
            login: Some("a".repeat(64)),
            org: None,
            basis: identity::TELEMETRY_LOGIN
        })
    );
}

#[test]
fn sidecar_absence_is_distinguished_from_failure() {
    let support = temp_dir("claude-request-identity-sidecars");
    assert!(crate::claude_local_otel::claude_sidecars_absent(&support, ROOT));
    let digest = format!("{:x}", Sha256::digest(ROOT.as_bytes()));
    let stores = fs::read_dir(&support).map(|entries| entries.count()).unwrap_or(0);
    assert_eq!(stores, 0);
    // A directory where the trace sidecar should be is a failure, not absence.
    let trace_dir = crate::claude_local_otel::claude_trace_ownership_evidence_dir(&support);
    fs::create_dir_all(trace_dir.join(format!("{digest}.jsonl"))).unwrap();
    assert!(!crate::claude_local_otel::claude_sidecars_absent(&support, ROOT));
    let _ = fs::remove_dir_all(support);
}

#[test]
fn bound_sessions_admit_this_scans_contract5_body_without_rewriting_the_owner() {
    let (dir, root, mut items) = claude_account_family_fixture();
    items.truncate(1);
    let api = (1..=4)
        .map(|n| {
            let mut row = complete_api_row(&root, &format!("req_{n}"), n, 10, 10, 0);
            if n > 2 {
                row.account_identifier_hash = Some("b".repeat(64));
            }
            signed(row)
        })
        .collect::<Vec<_>>();
    let trace = (1..=4)
        .map(|n| complete_trace_row(&root, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    let (api, trace) = reports(api, trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), healthy(), None);
    identity::apply_scan(&mut items, &evidence, &BTreeMap::new());
    assert!(items[0].usage_buckets[0].model_usage[0].identity_parts.is_some());
    let owner_key = sha256_hex(&["session_owner:v1", "machine", &items[0].source_session_id]);
    let bound = |index: &mut ScanIndex| {
        index.session_account_bindings.insert(
            owner_key.clone(),
            SessionAccountBinding {
                account_identifier_hash: "a".repeat(64),
                workspace_identifier_hash: None,
            },
        );
    };
    let mut index = ScanIndex::default();
    bound(&mut index);
    let mut without = items.clone();
    let deferred = index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        "machine",
        &mut without,
        &[],
        &claude_request_accounts::MixedUploads::default(),
    );
    assert_eq!(deferred.len(), 1, "no admission: today's veto applies");
    let mut admitted = claude_request_accounts::MixedUploads::default();
    admitted.admit_request_identity(&items[0]);
    let mut index = ScanIndex::default();
    bound(&mut index);
    let before = index.session_account_bindings.clone();
    let deferred = index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        "machine",
        &mut items,
        &[],
        &admitted,
    );
    assert!(deferred.is_empty());
    assert_eq!(index.session_account_bindings, before, "owner unchanged");
    // A body changed after admission is no longer admitted.
    let mut changed = items.clone();
    changed[0].input_tokens += 1;
    let mut index = ScanIndex::default();
    bound(&mut index);
    let deferred = index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        "machine",
        &mut changed,
        &[],
        &admitted,
    );
    assert_eq!(deferred.len(), 1);
    let _ = fs::remove_dir_all(dir);
}
