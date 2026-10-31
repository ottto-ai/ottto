// Contract-5 request identity: W0 r5 parity, builder, caps and classification.
use super::*;
use crate::snapshots::claude_request_identity::{
    self as identity, AuthorityKey, Contribution, DesktopCensus, MarkerVerdict, Refusal,
    RequestFacts, RequestIdentity, ScanEvidence, Tagged,
};

const W0_DIR: &str = "../../fixtures/session-identity";
/// The login `complete_api_row` reports by default.
const OWNER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const D64: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
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
        copy_unproven: row
            .get("copy_unproven")
            .and_then(Value::as_bool)
            .unwrap_or(false),
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
        identity_retained: row.get("identity_retained").is_some_and(|v| v == true),
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
        if tagged == "new-cap-evidence-16" {
            // Revised cap policy: this two-hour body can retain the newest
            // eight keys; W0's old whole-item fallback is no longer required.
            assert!(matches!(result, Tagged::Sent { refusals: 1 }), "{result:?}");
            assert!(built.usage_buckets[0].model_usage[0]
                .identity_parts
                .is_none());
            assert!(built.usage_buckets[1].model_usage[0]
                .identity_parts
                .is_some());
            assert_eq!(built.request_evidence.len(), 8);
            assert_eq!(identity::semantic_leaf(&built)["refused"], true);
            sticky_assert_reconciled(&built);
            continue;
        }
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

fn login_key(login: &str) -> RequestIdentity {
    RequestIdentity::Tagged(AuthorityKey {
        login: Some(login.to_string()),
        org: Some("d".repeat(64)),
        basis: identity::TELEMETRY,
    })
}

/// A login reaches the wire only as strictly lowercase hex of 8 to 128
/// characters, exactly as read.
#[test]
fn builder_tags_lowercase_hex_logins_at_the_length_bounds_verbatim() {
    let eight = "0123abcd".to_string();
    let max = "a".repeat(128);
    let digest = format!("{:x}", Sha256::digest(b"synthetic login"));
    let mut item = one_row_item(&[(10, Some("1")), (20, Some("2")), (30, Some("3"))]);
    let contributions = vec![
        contribution(&item, 10, Some("1"), login_key(&eight)),
        contribution(&item, 20, Some("2"), login_key(&max)),
        contribution(&item, 30, Some("3"), login_key(&digest)),
    ];
    assert_eq!(
        identity::apply(&mut item, &contributions),
        Ok(Tagged::Sent { refusals: 0 })
    );
    let wire = serde_json::to_string(&item).unwrap();
    for login in [&eight, &max, &digest] {
        assert!(wire.contains(&format!("\"{login}\"")), "{login}");
    }
}

/// Any other spelling refuses its own usage, which stays on the row untagged:
/// never rewritten into another login, never poisoning a valid key beside it.
#[test]
fn builder_refuses_logins_that_are_not_lowercase_hex() {
    let valid = "b".repeat(64);
    for invalid in [
        "C".repeat(64),
        "Abcdef01".to_string(),
        "g".repeat(64),
        format!("{}-", "e".repeat(63)),
        "abcdef0".to_string(),
        "a".repeat(129),
        String::new(),
    ] {
        let mut item = one_row_item(&[(10, Some("1")), (20, Some("2"))]);
        let before = item.model_usage.clone();
        let contributions = vec![
            contribution(&item, 10, Some("1"), login_key(&valid)),
            contribution(&item, 20, Some("2"), login_key(&invalid)),
        ];
        assert_eq!(
            identity::apply(&mut item, &contributions),
            Ok(Tagged::Sent { refusals: 1 }),
            "{invalid}"
        );
        let wire = serde_json::to_string(&item).unwrap();
        assert!(wire.contains(&format!("\"{valid}\"")), "{invalid}");
        if !invalid.is_empty() {
            for spelling in [invalid.clone(), invalid.to_ascii_lowercase()] {
                assert!(!wire.contains(&format!("\"{spelling}\"")), "{invalid}");
            }
        }
        // Usage and money are conserved on today's row.
        let strip = |rows: &[SnapshotModelUsage]| {
            rows.iter()
                .map(|row| (row.input_tokens, row.request_count, row.cost_usd.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(strip(&item.model_usage), strip(&before), "{invalid}");
        assert_eq!(item.provenance.collector, identity::COLLECTOR);
    }
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
                    // All eleven keys must be valid lowercase hex. The old
                    // a..k spelling made g..k refusal shares instead of keys.
                    identity: RequestIdentity::Tagged(AuthorityKey {
                        login: Some(format!("{login:064x}")),
                        org: Some("d".repeat(64)),
                        basis: identity::TELEMETRY,
                    }),
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

#[test]
fn over_cap_diagnostics_increment_each_reason_and_record_last_size() {
    use identity::OverCap;
    let reasons = BTreeSet::from([
        OverCap::EvidenceEntries,
        OverCap::AuthorityKeys,
        OverCap::PartsPerRow,
        OverCap::PartsPerItem,
        OverCap::Rows,
        OverCap::Bytes,
    ]);
    let (_, records) = crate::local_resource_diagnostics::capture(|| {
        crate::local_resource_diagnostics::claude_identity_over_cap(&reasons, 700_000);
        crate::local_resource_diagnostics::claude_identity_over_cap(&reasons, 800_000);
    });
    assert_eq!(records.len(), 2);
    let before = &records[0]["counts"]["claude_request_identity_over_cap"];
    let after = &records[1]["counts"]["claude_request_identity_over_cap"];
    for label in [
        "evidence_entries",
        "authority_keys",
        "parts_per_row",
        "parts_per_item",
        "rows",
        "bytes",
    ] {
        assert_eq!(
            after[label].as_u64().unwrap(),
            before[label].as_u64().unwrap() + 1
        );
    }
    assert_eq!(
        records[1]["counts"]["claude_request_identity_last_over_cap_item_bytes"],
        800_000
    );
    assert!(serde_json::to_vec(&records[1]).unwrap().len() < 2048);
}

#[test]
fn byte_cap_diagnostic_measures_tagged_attempt_and_preserves_full_strip() {
    let mut item = one_row_item(&[(10, None)]);
    let request = contribution(&item, 10, None, login_key(OWNER_A));
    identity::apply(&mut item, std::slice::from_ref(&request)).unwrap();
    // Unrelated body bytes can leave no room even for a single tagged bucket.
    item.session_display_name = Some("x".repeat(identity::MAX_ITEM_BYTES));
    let attempted_bytes = identity::item_bytes(&item);
    let mut expected = stripped(&item);
    expected.provenance.collector = identity::COLLECTOR.to_owned();
    expected.request_identity_refusals = 1;
    expected.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &expected);
    let (result, records) = crate::local_resource_diagnostics::capture(|| {
        identity::apply(&mut item, &[request]).unwrap()
    });
    let Tagged::Fallback { over_cap, refusals } = result else {
        panic!("{result:?}");
    };
    assert!(over_cap.contains(&identity::OverCap::Bytes));
    assert_eq!(refusals, 1);
    assert_eq!(
        serde_json::to_vec(&item).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["counts"]["claude_request_identity_last_over_cap_item_bytes"],
        attempted_bytes
    );
    assert!(
        records[0]["counts"]["claude_request_identity_over_cap"]["bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
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

fn facts<'a>(request_id: &'a str, at: Option<u64>, marker: MarkerVerdict<'a>) -> RequestFacts<'a> {
    RequestFacts {
        root: ROOT,
        source_session_id: ROOT,
        request_id,
        terminal_unix_seconds: at,
        event_clock_complete: true,
        marker,
        desktop: false,
        scan_unix_seconds: Some(1_000_000),
        email_home: None,
        session_start_unix_seconds: None,
        duplicated_elsewhere: false,
    }
}

fn root_set() -> BTreeSet<String> {
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
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
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
            &facts("req_login", at, MarkerVerdict::Trusted(&org_d))
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
            &facts("req_login", at, MarkerVerdict::Trusted(&org_e))
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
    // a witnessed healthy writer; otherwise missing and open to transcript
    // evidence. Production has no qualified writer witness (SESSION ruling
    // pending), so a young missing request is missing there.
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_new", Some(999_900), MarkerVerdict::None)
        ),
        RequestIdentity::Missing
    );
    let witnessed = ScanEvidence::new(&api, &trace, BTreeSet::new(), None)
        .with_pending_writer_witnesses(root_set());
    assert_eq!(
        identity::classify(
            &witnessed,
            &facts("req_new", Some(999_900), MarkerVerdict::None)
        ),
        RequestIdentity::Refused(Refusal::Pending)
    );
    assert_eq!(
        identity::classify(
            &witnessed,
            &facts("req_old", Some(999_000), MarkerVerdict::None)
        ),
        RequestIdentity::Missing
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_old", Some(999_000), MarkerVerdict::None)
        ),
        RequestIdentity::Missing
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_old", Some(999_000), MarkerVerdict::Trusted(&org_e))
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
    let unreadable = ScanEvidence::new(&api, &trace, root_set(), None);
    assert_eq!(
        identity::classify(
            &unreadable,
            &facts("req_old", Some(999_000), MarkerVerdict::Trusted(&org_e))
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
        let mut request = facts("req_old", Some(999_000), MarkerVerdict::Trusted(&org));
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
    // Production suppresses the basis until the receiver's time-scoped veto
    // is verified: a qualifying census still yields org-only.
    let suppressed = ScanEvidence::new(
        &api,
        &trace,
        BTreeSet::new(),
        Some(census(999_500, &[LOGIN_A])),
    );
    assert_eq!(
        desktop(&suppressed, true),
        org_only,
        "sole login suppressed"
    );
    let fresh = ScanEvidence::new(
        &api,
        &trace,
        BTreeSet::new(),
        Some(census(999_500, &[LOGIN_A])),
    )
    .with_sole_login_enabled();
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
        Some(census(998_000, &[LOGIN_A])),
    )
    .with_sole_login_enabled();
    assert_eq!(
        desktop(&stale, true),
        org_only,
        "census older than the request"
    );
    let two = ScanEvidence::new(
        &api,
        &trace,
        BTreeSet::new(),
        Some(census(999_500, &[LOGIN_A, "b"])),
    )
    .with_sole_login_enabled();
    assert_eq!(desktop(&two, true), org_only);
    let none = ScanEvidence::new(&api, &trace, BTreeSet::new(), None).with_sole_login_enabled();
    assert_eq!(desktop(&none, true), org_only);
}

/// SESSION ruling: a trace owner outranks the transcript. A request whose
/// owner is foreign, duplicated or unpaired is refused and never borrows this
/// transcript's org or sole login, even where both would otherwise qualify.
#[test]
fn trace_owned_requests_refuse_before_any_transcript_basis() {
    let org = "d".repeat(64);
    let child = format!("{ROOT}_agent-child");
    let mut forged = complete_trace_row(ROOT, "req_forged", "");
    forged.fingerprint = format!("sha256:{}", "0".repeat(64));
    let trace = vec![
        complete_trace_row(ROOT, "req_paired", ""),
        complete_trace_row(ROOT, "req_sibling", "child"),
        complete_trace_row(ROOT, "req_unpaired", ""),
        complete_trace_row(ROOT, "req_dup", ""),
        complete_trace_row(ROOT, "req_dup", ""),
        forged,
    ];
    let (api, trace) = reports(
        vec![complete_api_row(ROOT, "req_paired", 1, 10, 1, 0)],
        trace,
    );
    let census = DesktopCensus {
        completed_at_unix_seconds: 999_500,
        logins_by_org: BTreeMap::from([(org.clone(), BTreeSet::from([LOGIN_A.to_string()]))]),
    };
    let evidence =
        ScanEvidence::new(&api, &trace, BTreeSet::new(), Some(census)).with_sole_login_enabled();
    let classify = |request_id: &str, source_session_id: &str| {
        let mut request = facts(request_id, Some(999_000), MarkerVerdict::Trusted(&org));
        request.source_session_id = source_session_id;
        request.desktop = true;
        identity::classify(&evidence, &request)
    };
    let refused = RequestIdentity::Refused;
    // Foreign: another child's request, a parent's request seen from a
    // child, or an owner record that fails its own integrity checks.
    assert_eq!(
        classify("req_sibling", ROOT),
        refused(Refusal::ForeignOwner)
    );
    assert_eq!(
        classify("req_unpaired", &child),
        refused(Refusal::ForeignOwner)
    );
    assert_eq!(classify("req_forged", ROOT), refused(Refusal::ForeignOwner));
    // Incomplete: the owner is this session but its telemetry row is missing.
    assert_eq!(
        classify("req_unpaired", ROOT),
        refused(Refusal::IncompleteEvidence)
    );
    assert_eq!(
        classify("req_sibling", &child),
        refused(Refusal::IncompleteEvidence)
    );
    assert_eq!(
        classify("req_dup", ROOT),
        refused(Refusal::ConflictingDuplicate)
    );
    // Controls: a valid paired owner keeps telemetry; no owner keeps the
    // transcript bases.
    assert_eq!(
        classify("req_paired", ROOT),
        RequestIdentity::Tagged(AuthorityKey {
            login: Some(OWNER_A.to_string()),
            org: None,
            basis: identity::TELEMETRY_LOGIN,
        })
    );
    assert_eq!(
        classify("req_none", ROOT),
        RequestIdentity::Tagged(AuthorityKey {
            login: Some(LOGIN_A.to_string()),
            org: Some(org.clone()),
            basis: identity::TRANSCRIPT_SOLE_LOGIN,
        })
    );
    let mut terminal = facts("req_none", Some(999_000), MarkerVerdict::Trusted(&org));
    terminal.desktop = false;
    assert_eq!(
        identity::classify(&evidence, &terminal),
        RequestIdentity::Tagged(AuthorityKey {
            login: None,
            org: Some(org.clone()),
            basis: identity::TRANSCRIPT_ORG,
        })
    );
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
            desktop_session_id: None,
            spawned_from_desktop_session_id: None,
            spawned_from_unresolved: false,
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
            desktop_session_id: None,
            spawned_from_desktop_session_id: None,
            spawned_from_unresolved: false,
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

#[test]
fn desktop_census_witness_follows_the_store_inventory_through_retry_backoff() {
    const NOW: u64 = 1_800_000_000; // 2027-01-15T08:00:00Z
    let swept = BTreeSet::from([PathBuf::from("/synthetic/store-a")]);
    let backed_off = |store_dirs: &BTreeSet<PathBuf>| {
        let mut index = ScanIndex {
            claude_desktop_identity_census_complete: true,
            claude_desktop_census_witness: Some(identity::DesktopCensusWitness::new(
                NOW - 30,
                &swept,
            )),
            claude_desktop_store_retry_not_before_unix_seconds: Some(NOW + 30),
            ..ScanIndex::default()
        };
        let metadata = ClaudeTitleMetadata::load_from_store_dirs_with_index(
            store_dirs,
            &mut index,
            "2027-01-15T08:00:00Z",
            true,
        );
        assert!(metadata.sidecar_census_incomplete);
        assert_eq!(
            index.claude_desktop_store_retry_not_before_unix_seconds,
            Some(NOW + 30),
            "still inside the backoff: no sweep ran"
        );
        index
    };
    let unchanged = backed_off(&swept);
    assert!(unchanged.claude_desktop_census_witness.is_some());
    assert!(
        identity::desktop_census_at(&unchanged, NOW).is_some(),
        "control"
    );
    for changed in [
        BTreeSet::from([
            PathBuf::from("/synthetic/store-a"),
            PathBuf::from("/synthetic/store-b"),
        ]),
        BTreeSet::from([PathBuf::from("/synthetic/store-b")]),
        BTreeSet::new(),
    ] {
        let index = backed_off(&changed);
        assert_eq!(index.claude_desktop_census_witness, None, "{changed:?}");
        assert_eq!(
            identity::desktop_census_at(&index, NOW),
            None,
            "{changed:?}"
        );
    }
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
        MarkerVerdict::Trusted(&org_hash(ORG_1))
    );
    assert_eq!(
        markers.verdict(2, false),
        MarkerVerdict::Trusted(&org_hash(ORG_1))
    );
    assert_eq!(markers.verdict(3, false), MarkerVerdict::UntrustedFlip);
    assert_eq!(
        markers.verdict(3, true),
        MarkerVerdict::Trusted(&org_hash(ORG_2)),
        "Desktop markers are trusted"
    );
    assert_eq!(
        markers.verdict(9, false),
        MarkerVerdict::Trusted(&org_hash(ORG_1)),
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
        MarkerVerdict::Trusted(&org_hash(ORG_1))
    );
    assert!(!serde_json::to_string(&items[0])
        .unwrap()
        .contains("credential_org"));
    let _ = fs::remove_dir_all(dir);
}

// --- End to end on both usage paths -------------------------------------------

#[test]
fn transcript_path_tags_parsed_requests_from_their_own_telemetry() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let before = items[0].clone();
    let outcome = identity::apply_scan(&mut items, &evidence, BTreeMap::new());
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

/// D1 leaves new-collector items alone, so contract 5 must apply the same
/// lifecycle spelling D1 applies; the lifecycle component may not drift.
#[test]
fn contract5_lifecycle_matches_the_legacy_qualification_path() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, mut items) = claude_account_family_fixture();
    items.truncate(1);
    items[0].source_started_at = Some("2026-08-02T10:00:00.500+03:00".to_string());
    items[0].source_ended_at = Some("2026-08-02T10:30:00+03:00".to_string());
    items[0].source_last_activity_at = Some("2026-08-02T10:29:59.000-00:00".to_string());
    let api = (1..=4)
        .map(|n| signed(complete_api_row(&root, &format!("req_{n}"), n, 10, 10, 0)))
        .collect::<Vec<_>>();
    let trace = (1..=4)
        .map(|n| complete_trace_row(&root, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    let (api, trace) = reports(api, trace);
    let original = items.clone();
    let mut legacy = items.clone();
    claude_request_accounts::apply(&mut legacy, &api, &trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let outcome = identity::apply_scan(&mut items, &evidence, BTreeMap::new());
    assert_eq!(outcome.sent, 1, "{outcome:?}");
    claude_request_accounts::apply(&mut items, &api, &trace);
    let (old, new) = (&legacy[0], &items[0]);
    assert_eq!(new.provenance.collector, identity::COLLECTOR);
    assert_eq!(
        old.source_started_at.as_deref(),
        Some("2026-08-02T07:00:00.5Z")
    );
    for (old, new) in [
        (&old.source_started_at, &new.source_started_at),
        (&old.source_ended_at, &new.source_ended_at),
        (&old.source_last_activity_at, &new.source_last_activity_at),
    ] {
        assert_eq!(old, new);
    }
    let lifecycle = |item: &SnapshotItem| {
        snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, item)["lifecycle_activity"]
            .clone()
    };
    assert_eq!(lifecycle(old), lifecycle(new));
    assert_eq!(
        new.snapshot_fingerprint,
        snapshot_fingerprint(SnapshotSource::ClaudeCode, new)
    );
    // An item whose rows contract 5 cannot reproduce returns to D1 unchanged.
    let mut untagged = original;
    untagged[0].usage_buckets[0].model_usage[0].request_count += 1;
    let before = serde_json::to_vec(&untagged).unwrap();
    let outcome = identity::apply_scan(&mut untagged, &evidence, BTreeMap::new());
    assert_eq!(outcome.ineligible, 1, "{outcome:?}");
    assert_eq!(serde_json::to_vec(&untagged).unwrap(), before);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reported_path_tags_from_rebuild_groupings() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, mut items) = claude_account_family_fixture();
    items.truncate(1);
    let mut item = items.remove(0);
    let mut api = Vec::new();
    for request_id in item.claude_usage_occurrences.keys() {
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
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    // What `rebuild_claude_reported_usage` feeds the sink, request by request.
    let mut sink = identity::RequestSink::for_item(&evidence, &item, usize::MAX).unwrap();
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
        sink.add(
            &item,
            identity::Request {
                request_id,
                occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
                timestamp: occurrence.timestamp.as_deref().unwrap(),
                bucket_start: "2026-08-02T07:00:00Z",
                row_key: &row_key,
                usage: &usage,
            },
        );
    }
    let groupings = BTreeMap::from([(item.source_session_id.clone(), sink.finish())]);
    let mut items = vec![item];
    let outcome = identity::apply_scan(&mut items, &evidence, groupings);
    assert_eq!(outcome.sent, 1, "{outcome:?}");
    let parts = items[0].usage_buckets[0].model_usage[0]
        .identity_parts
        .clone()
        .unwrap();
    assert_eq!(parts.len(), 2);
    assert!(parts
        .iter()
        .all(|part| part.cost_usd == Some("0.0002".to_string())));
    // A reported item without this pass's grouping stays on today's path.
    let mut ungrouped = vec![items[0].clone()];
    ungrouped[0].provenance.collector = "claude_code_jsonl".to_string();
    let outcome = identity::apply_scan(&mut ungrouped, &evidence, BTreeMap::new());
    assert_eq!(outcome.ineligible, 1, "{outcome:?}");
    let _ = fs::remove_dir_all(dir);
}

const CHILD_AGENT: &str = "a4d1585d310070d0f";

/// The fixture family's telemetry: one row per transcript request and, with
/// `aux`, two telemetry-only requests of the parent: a Haiku side call and a
/// call whose only cache usage is aggregate cache creation. `aux_login: false`
/// leaves both without a login of their own.
fn family_reports(
    parent: &str,
    aux: bool,
    aux_login: bool,
) -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let mut api_rows = (1..=4)
        .map(|n| signed(complete_api_row(parent, &format!("req_{n}"), n, 10, 10, 0)))
        .collect::<Vec<_>>();
    api_rows.push(signed(complete_api_row(parent, "req_5", 5, 10, 1, 0)));
    let mut trace_rows = (1..=4)
        .map(|n| complete_trace_row(parent, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    trace_rows.push(complete_trace_row(parent, "req_5", CHILD_AGENT));
    if aux {
        let mut haiku = complete_api_row(parent, "req_aux_haiku", 6, 7, 3, 0);
        haiku.model = "claude-3-5-haiku-20241022".to_string();
        haiku.observed_at = "2026-08-02T07:00:40Z".to_string();
        let mut cache = complete_api_row(parent, "req_prompt_suggestion", 7, 3, 2, 7);
        cache.observed_at = "2026-08-02T08:14:00Z".to_string();
        for mut row in [haiku, cache] {
            if !aux_login {
                row.account_identifier_hash = None;
            }
            trace_rows.push(complete_trace_row(parent, &row.request_id, ""));
            api_rows.push(signed(row));
        }
    }
    (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(parent.to_string(), api_rows)]),
            health: Default::default(),
        },
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(parent.to_string(), trace_rows)]),
            ..Default::default()
        },
    )
}

fn family_index_keys(dir: &Path, parent: &str) -> [String; 2] {
    [
        local_index_key(&dir.join(format!("{parent}.jsonl"))),
        local_index_key(
            &dir.join(parent)
                .join("subagents")
                .join(format!("agent-{CHILD_AGENT}.jsonl")),
        ),
    ]
}

/// (requests, unattributed tokens) of the bucket rows per tagged login, and
/// of their untagged usage.
fn identity_shares(item: &SnapshotItem) -> (BTreeMap<String, (u64, u64)>, (u64, u64)) {
    let mut tagged = BTreeMap::<String, (u64, u64)>::new();
    let mut untagged = (0, 0);
    let mut add =
        |evidence_ref: Option<u16>, login: Option<&String>, requests: u64, unattributed: u64| {
            let share = match evidence_ref {
                Some(_) => tagged
                    .entry(login.cloned().unwrap_or_default())
                    .or_default(),
                None => &mut untagged,
            };
            share.0 += requests;
            share.1 += unattributed;
        };
    for row in item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
    {
        match &row.identity_parts {
            Some(parts) => {
                for part in parts {
                    add(
                        part.evidence_ref,
                        part.account_identifier_hash.as_ref(),
                        part.request_count,
                        part.unattributed_total_tokens,
                    );
                }
            }
            None => add(
                row.evidence_ref,
                row.account_identifier_hash.as_ref(),
                row.request_count,
                row.unattributed_total_tokens,
            ),
        }
    }
    (tagged, untagged)
}

/// Tagging moved no usage or money: totals and every row are today's.
fn assert_usage_conserved(tagged: &SnapshotItem, before: &SnapshotItem) {
    let totals = |item: &SnapshotItem| {
        (
            item.request_count,
            item.input_tokens,
            item.output_tokens,
            item.cache_read_tokens,
            item.cache_creation_5m_tokens,
            item.cache_creation_1h_tokens,
            item.reasoning_output_tokens,
            item.unattributed_total_tokens,
        )
    };
    assert_eq!(totals(tagged), totals(before));
    assert_eq!(tagged.cost, before.cost);
    let (tagged, before) = (stripped(tagged), stripped(before));
    assert_eq!(
        serde_json::to_value(&tagged.model_usage).unwrap(),
        serde_json::to_value(&before.model_usage).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&tagged.usage_buckets).unwrap(),
        serde_json::to_value(&before.usage_buckets).unwrap()
    );
}

/// The real reported rebuild, with and without contract-5 evidence: its own
/// output is unchanged, each rebuilt item gets a grouping, and tagging then
/// conserves every count. Telemetry-only (auxiliary) requests the rebuild
/// admits keep the item contract 5. Each is classified on its own telemetry
/// row, never on the transcript's: with or without a login of its own, its
/// observer clock cannot qualify, so its usage stays on its row untagged and
/// refused while the transcript requests keep their telemetry login.
#[test]
fn reported_rebuild_groups_requests_without_changing_its_output() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    for (with_aux, aux_login) in [(false, true), (true, true), (true, false)] {
        let (dir, parent, items) = claude_account_family_fixture();
        let (api, trace) = family_reports(&parent, with_aux, aux_login);
        let index = || {
            let mut index = ScanIndex::default();
            for key in family_index_keys(&dir, &parent) {
                index.files.insert(key, manifest_index_entry(None));
            }
            index
        };
        let mut plain = items.clone();
        let plain_disposition = apply_claude_reported_usage_with_index(
            &mut plain,
            &api,
            &trace,
            &mut index(),
            true,
            "2026-08-02T07:10:00Z",
        );
        assert!(plain_disposition.request_groupings.is_empty());
        let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        let mut grouped = items;
        let mut disposition = apply_claude_reported_usage_with_identity(
            &mut grouped,
            &api,
            &trace,
            &mut index(),
            true,
            "2026-08-02T07:10:00Z",
            Some(&evidence),
        );
        assert_eq!(
            serde_json::to_vec(&grouped).unwrap(),
            serde_json::to_vec(&plain).unwrap()
        );
        assert!(grouped.iter().all(|item| {
            item.usage_accounting_contract.as_deref() == Some("session_exclusive_reported_usage:v1")
        }));
        assert_eq!(disposition.request_groupings.len(), 2);
        let groupings = std::mem::take(&mut disposition.request_groupings);
        if with_aux {
            assert_eq!(grouped[0].request_count, 6);
            assert_eq!(grouped[0].claude_usage_request_ids.len(), 4);
            // The admitted requests must be exactly the item's: a transcript
            // request the rebuild did not admit, or a count it did not make,
            // keeps today's path and bytes.
            for skew in 0..2 {
                let mut skewed = grouped.clone();
                if skew == 0 {
                    skewed[0]
                        .claude_usage_request_ids
                        .insert("req_unadmitted".to_string());
                } else {
                    skewed[0].request_count += 1;
                }
                let untouched = serde_json::to_vec(&skewed[0]).unwrap();
                let outcome = identity::apply_scan(&mut skewed, &evidence, groupings.clone());
                assert_eq!(
                    outcome,
                    identity::ScanOutcome {
                        sent: 1,
                        ineligible: 1,
                        ..Default::default()
                    },
                    "skew={skew}"
                );
                assert_eq!(serde_json::to_vec(&skewed[0]).unwrap(), untouched);
            }
        }
        let before = grouped.clone();
        let outcome = identity::apply_scan(&mut grouped, &evidence, groupings);
        assert_eq!(
            outcome,
            identity::ScanOutcome {
                sent: 2,
                ..Default::default()
            },
            "with_aux={with_aux} aux_login={aux_login}"
        );
        for (tagged, before) in grouped.iter().zip(&before) {
            assert_eq!(tagged.provenance.collector, identity::COLLECTOR);
            assert_usage_conserved(tagged, before);
        }
        if with_aux {
            let (logins, untagged) = identity_shares(&grouped[0]);
            assert_eq!(logins, BTreeMap::from([(OWNER_A.to_string(), (4, 0))]));
            assert_eq!(untagged, (2, 7), "both auxiliary requests, all their usage");
            // One refused row per auxiliary request: each has its own row.
            assert_eq!(grouped[0].request_identity_refusals, 2);
            assert!(grouped[0]
                .request_evidence
                .iter()
                .all(|entry| entry.identity_basis == identity::TELEMETRY_LOGIN));
        }
        for tagged in grouped.iter().skip(usize::from(with_aux)) {
            assert_eq!(tagged.request_identity_refusals, 0);
            assert_eq!(
                tagged.usage_buckets[0].model_usage[0]
                    .account_identifier_hash
                    .as_deref(),
                Some("a".repeat(64).as_str())
            );
        }
        let _ = fs::remove_dir_all(dir);
    }
}

/// F1 repair path. A complete census that proves a family re-arms each member
/// that pass did not parse (the existing earlier-page re-arm), so the next
/// pass re-parses it and rebuilds its reported body from the family witness.
/// Before telemetry-only requests were admitted, that body reached D1 and
/// became the unknown-account collector; now it is contract 5, also under an
/// unsettled census, with a fingerprint the upload no-op check cannot match.
#[test]
fn proven_reported_members_are_rearmed_and_reoffered_as_contract5() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::claude_request_accounts as accounts;
    const WINDOW: &str = "2026-08-02T07:10:00Z";
    const NEXT_WINDOW: &str = "2026-08-02T07:20:00Z";
    let (dir, parent, items) = claude_account_family_fixture();
    let (api, trace) = family_reports(&parent, true, true);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let keys = family_index_keys(&dir, &parent);
    let mut index = ScanIndex::default();
    for key in &keys {
        index.files.insert(key.clone(), manifest_index_entry(None));
    }
    let armed = |index: &ScanIndex| {
        keys.iter()
            .map(|key| {
                index
                    .files
                    .get(key)
                    .unwrap()
                    .source_file_fingerprint
                    .is_empty()
            })
            .collect::<Vec<_>>()
    };

    // Page A observes both members; nothing is proven yet.
    let mut page_a = items.clone();
    apply_claude_reported_usage_with_identity(
        &mut page_a,
        &api,
        &trace,
        &mut index,
        false,
        WINDOW,
        Some(&evidence),
    );
    assert!(page_a
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    assert_eq!(armed(&index), [false, false]);

    // Page B completes the census without parsing them and proves the family.
    apply_claude_reported_usage_with_identity(
        &mut [],
        &api,
        &trace,
        &mut index,
        true,
        WINDOW,
        Some(&evidence),
    );
    assert!(index.claude_usage_family_witnesses.contains_key(&parent));
    assert_eq!(armed(&index), [true, true], "both members re-armed");

    // The next pass re-parses them under an incomplete (unsettled) census.
    let mut reparsed = items;
    let mut disposition = apply_claude_reported_usage_with_identity(
        &mut reparsed,
        &api,
        &trace,
        &mut index,
        false,
        NEXT_WINDOW,
        Some(&evidence),
    );
    assert!(!disposition.duplicate_census.census_complete);
    assert!(reparsed.iter().all(|item| {
        item.usage_accounting_contract.as_deref() == Some("session_exclusive_reported_usage:v1")
    }));
    assert_eq!(reparsed[0].request_count, 6);
    let before = reparsed.clone();
    // What the same pass emitted before: the untagged body through D1.
    let mut legacy = reparsed.clone();
    let _ =
        accounts::apply_with_shared_index(&mut legacy, &api, &trace, &BTreeMap::new(), &evidence);
    assert_eq!(legacy[0].provenance.collector, accounts::UNKNOWN);

    let ownership = identity::TranscriptOwnership::after_census(&index, &disposition);
    let outcome = identity::apply_scan_with_ownership(
        &mut reparsed,
        &evidence,
        std::mem::take(&mut disposition.request_groupings),
        &ownership,
    );
    assert_eq!(
        outcome,
        identity::ScanOutcome {
            sent: 2,
            ..Default::default()
        }
    );
    let _ =
        accounts::apply_with_shared_index(&mut reparsed, &api, &trace, &BTreeMap::new(), &evidence);
    let tagged = &reparsed[0];
    assert_eq!(tagged.provenance.collector, identity::COLLECTOR);
    assert_ne!(tagged.snapshot_fingerprint, legacy[0].snapshot_fingerprint);
    assert_eq!(
        tagged.snapshot_fingerprint,
        snapshot_fingerprint(SnapshotSource::ClaudeCode, tagged)
    );
    assert_usage_conserved(tagged, &before[0]);
    let (logins, untagged) = identity_shares(tagged);
    assert_eq!(logins, BTreeMap::from([(OWNER_A.to_string(), (4, 0))]));
    assert_eq!(untagged, (2, 7));
    assert_eq!(reparsed[1].provenance.collector, identity::COLLECTOR);
    let _ = fs::remove_dir_all(dir);
}

const LEGACY_PARENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const LEGACY_CHILD: &str = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
const LEGACY_WINDOW: &str = "2026-08-02T07:10:00Z";

fn legacy_line(session: &str, second: u64, request_id: &str, input: u64, output: u64) -> String {
    format!(
        r#"{{"uuid":"u-{request_id}","timestamp":"2026-08-02T07:00:{second:02}Z","type":"assistant","sessionId":"{session}","requestId":"{request_id}","message":{{"id":"msg_{request_id}","model":"claude-haiku-4-5","usage":{{"input_tokens":{input},"output_tokens":{output}}}}}}}"#
    ) + "\n"
}

/// A top-level fork written before `forkedFrom` existed: the child copies the
/// parent's first response (`req_shared`, owned by the parent's telemetry
/// under its own login) and then makes two of its own. The child's telemetry
/// also holds `aux` telemetry-only requests: an aggregate cache-creation call
/// and then a Haiku side call. Returns the raw parsed items, the reports, and
/// the item index both members are tracked by.
fn legacy_fork_fixture(
    aux: usize,
) -> (
    PathBuf,
    Vec<SnapshotItem>,
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ScanIndex,
) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = temp_dir(&format!(
        "claude-legacy-fork-c5-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let parent_path = dir.join(format!("{LEGACY_PARENT}.jsonl"));
    let child_path = dir.join(format!("{LEGACY_CHILD}.jsonl"));
    fs::write(
        &parent_path,
        legacy_line(LEGACY_PARENT, 1, "req_shared", 900, 90)
            + &legacy_line(LEGACY_PARENT, 2, "req_parent", 11, 3),
    )
    .unwrap();
    fs::write(
        &child_path,
        legacy_line(LEGACY_CHILD, 1, "req_shared", 900, 90)
            + &legacy_line(LEGACY_CHILD, 3, "req_child", 12, 4)
            + &legacy_line(LEGACY_CHILD, 4, "req_child_2", 14, 5),
    )
    .unwrap();
    let mut items =
        parse_claude_code_jsonl_file(&parent_path, "2026-08-02T07:01:00Z", "parent-fp".into())
            .unwrap();
    items.extend(
        parse_claude_code_jsonl_file(&child_path, "2026-08-02T07:01:00Z", "child-fp".into())
            .unwrap(),
    );
    assert_eq!(items[1].request_count, 3, "the raw child counts the prefix");

    let parent_rows = [("req_shared", 1, 900, 90), ("req_parent", 2, 11, 3)]
        .into_iter()
        .map(|(request_id, n, input, output)| {
            let mut row = complete_api_row(LEGACY_PARENT, request_id, n, input, output, 0);
            row.account_identifier_hash = Some("b".repeat(64));
            signed(row)
        })
        .collect::<Vec<_>>();
    let mut child_rows = vec![
        signed(complete_api_row(LEGACY_CHILD, "req_child", 3, 12, 4, 0)),
        signed(complete_api_row(LEGACY_CHILD, "req_child_2", 4, 14, 5, 0)),
    ];
    let mut cache = complete_api_row(LEGACY_CHILD, "req_aux_cache", 7, 3, 2, 7);
    cache.observed_at = "2026-08-02T08:14:00Z".to_string();
    let mut haiku = complete_api_row(LEGACY_CHILD, "req_aux_haiku", 6, 7, 3, 0);
    haiku.model = "claude-3-5-haiku-20241022".to_string();
    haiku.observed_at = "2026-08-02T07:00:40Z".to_string();
    child_rows.extend([cache, haiku].into_iter().take(aux).map(signed));
    let trace = |root: &str, rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence]| {
        rows.iter()
            .map(|row| complete_trace_row(root, &row.request_id, ""))
            .collect::<Vec<_>>()
    };
    let trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([
            (
                LEGACY_PARENT.to_string(),
                trace(LEGACY_PARENT, &parent_rows),
            ),
            (LEGACY_CHILD.to_string(), trace(LEGACY_CHILD, &child_rows)),
        ]),
        ..Default::default()
    };
    let api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([
            (LEGACY_PARENT.to_string(), parent_rows),
            (LEGACY_CHILD.to_string(), child_rows),
        ]),
        health: Default::default(),
    };
    let mut index = ScanIndex::default();
    for path in [&parent_path, &child_path] {
        index
            .files
            .insert(local_index_key(path), manifest_index_entry(None));
    }
    (dir, items, api_report, trace_report, index)
}

fn request_hash(request_id: &str) -> String {
    format!("{:x}", Sha256::digest(request_id.as_bytes()))
}

/// A legacy fork whose inherited prefix the reported rebuild excludes stays
/// contract 5 by exact owned-request accounting, with or without
/// telemetry-only requests. The excluded request is never counted,
/// classified or tagged in the child: its usage stays the parent's, and the
/// parent's own login never reaches the child. With one telemetry-only request
/// (excluded count == auxiliary count) the 0.1.172 request-id count guard also
/// admits the child, so this repair takes no such item off contract 5.
#[test]
fn legacy_excluded_reported_fork_stays_contract5_by_owned_requests() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let parent_login = "b".repeat(64);
    // One auxiliary request first: the item 0.1.172 already sent as contract 5.
    for aux in [1, 0, 2] {
        let (dir, mut items, api, trace, mut index) = legacy_fork_fixture(aux);
        let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        let mut disposition = apply_claude_reported_usage_with_identity(
            &mut items,
            &api,
            &trace,
            &mut index,
            true,
            LEGACY_WINDOW,
            Some(&evidence),
        );
        assert!(
            items
                .iter()
                .all(|item| item.usage_accounting_contract.as_deref()
                    == Some("session_exclusive_reported_usage:v1")),
            "aux={aux}"
        );
        assert_eq!(
            index.claude_usage_family_witnesses[LEGACY_CHILD].legacy_excluded_request_id_hashes,
            BTreeMap::from([(
                LEGACY_CHILD.to_string(),
                BTreeSet::from([request_hash("req_shared")])
            )])
        );
        let child = &items[1];
        let aux_count = u64::try_from(aux).unwrap();
        // The excluded prefix is outside the child's count and usage.
        assert_eq!(child.claude_usage_request_ids.len(), 3);
        assert!(child.claude_usage_request_ids.contains("req_shared"));
        assert_eq!(child.request_count, 2 + aux_count, "aux={aux}");
        assert_eq!(
            child.input_tokens,
            12 + 14 + [3, 7].iter().take(aux).sum::<u64>()
        );
        assert_eq!(
            child.output_tokens,
            4 + 5 + [2, 3].iter().take(aux).sum::<u64>()
        );
        // The parent keeps the shared request's usage.
        assert_eq!(items[0].request_count, 2);
        assert_eq!(items[0].input_tokens, 911);
        let grouping = &disposition.request_groupings[LEGACY_CHILD];
        assert!(grouping.owned_reported_requests(child), "aux={aux}");
        assert_eq!(
            claude_snapshot_request_id_hashes(child).is_some(),
            aux == 1,
            "the 0.1.172 guard admits only a coincidental count"
        );
        let before = items.clone();
        let ownership = identity::TranscriptOwnership::after_census(&index, &disposition);
        let outcome = identity::apply_scan_with_ownership(
            &mut items,
            &evidence,
            std::mem::take(&mut disposition.request_groupings),
            &ownership,
        );
        assert_eq!(
            outcome,
            identity::ScanOutcome {
                sent: 2,
                ..Default::default()
            },
            "aux={aux}"
        );
        for (tagged, before) in items.iter().zip(&before) {
            assert_eq!(tagged.provenance.collector, identity::COLLECTOR);
            assert_usage_conserved(tagged, before);
        }
        let (logins, untagged) = identity_shares(&items[1]);
        assert_eq!(logins, BTreeMap::from([(OWNER_A.to_string(), (2, 0))]));
        assert_eq!(untagged, (aux_count, if aux > 0 { 7 } else { 0 }));
        assert_eq!(items[1].request_identity_refusals, aux_count);
        assert!(!serde_json::to_string(&items[1])
            .unwrap()
            .contains(&parent_login));
        let (parent_logins, parent_untagged) = identity_shares(&items[0]);
        assert_eq!(
            parent_logins,
            BTreeMap::from([(parent_login.clone(), (2, 0))])
        );
        assert_eq!(parent_untagged, (0, 0));
        let _ = fs::remove_dir_all(dir);
    }
}

/// A quiet off-page family member must not lose Full authority on a
/// debt-free Unchanged retry. Both protected-list states use legacy money,
/// including copied-prefix exclusion and telemetry-only usage.
#[cfg(unix)]
#[test]
fn unchanged_census_keeps_off_page_family_proof_and_legacy_money_after_reload() {
    // Like the sampled production reuse fixtures, this requires a platform
    // whose heap layout permits retaining the Full read's native reduction.
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::claude_reemission_exclusions::ReemissionExclusions;
    use crate::snapshots::claude_request_census::{
        record_claude_request_census, ClaudeRequestCensusParse,
    };
    use crate::transcript_acquisition::{ReadMode, Scope};

    for paused in [false, true] {
        let (dir, _, api, trace, mut index) = legacy_fork_fixture(1);
        index.claude_reemission_exclusions = ReemissionExclusions::parse(
            if paused {
                "invalid".to_string()
            } else {
                format!(
                    "{}\n{}",
                    request_hash(LEGACY_PARENT),
                    request_hash(LEGACY_CHILD)
                )
            }
            .as_bytes(),
        );
        assert!(!claude_request_money::e2::family_applies(
            &index,
            LEGACY_CHILD,
            None
        ));
        let quiet_path = dir.join(LEGACY_CHILD).join("subagents/agent-quiet.jsonl");
        fs::create_dir_all(quiet_path.parent().unwrap()).unwrap();
        fs::write(&quiet_path, "").unwrap();
        let key = local_index_key(&quiet_path);
        let cache = std::sync::Arc::new(sampled_scan::SharedCache::default());
        let run = |index: ScanIndex| {
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&dir),
                index,
                LEGACY_WINDOW,
                365,
                1000,
                true,
                None,
                &[],
                false,
                true,
            )
            .with_sampled_acquisition(cache.clone(), Scope("unchanged-census".into()));
            let mut mode = None;
            loop {
                if let Some(active) = scan.active_file.as_ref() {
                    if local_index_key(&active.candidate.path) == key {
                        mode = active.sampling.as_ref().map(|active| active.mode);
                    }
                }
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => break (index, scan, mode),
                }
            }
        };
        let (mut index, full, mode) = run(index);
        assert!(matches!(mode, Some(ReadMode::Full(_))));
        let checkpoint = cache
            .retained_checkpoint(&key)
            .expect("the quiet member's Full read must retain its native reduction");
        assert!(checkpoint.audit_debt().is_none());
        let verified = index.claude_request_census.get(&key).unwrap().clone();
        assert!(!verified.unverified_for_test());
        let raw = full.snapshots;
        let mut before = raw.clone();
        apply_claude_reported_usage_with_identity(
            &mut before,
            &api,
            &trace,
            &mut index,
            true,
            LEGACY_WINDOW,
            None,
        );
        let expected = before
            .iter()
            .find(|item| item.source_session_id == LEGACY_CHILD)
            .unwrap();
        assert_eq!(
            expected.usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
        assert!(expected.cost.is_some());
        assert_eq!(expected.request_count, 3); // two owned plus telemetry-only
        assert_eq!(expected.input_tokens, 29); // 12 + 14 + 3, no copied 900
        let witness = index.claude_usage_family_witnesses[LEGACY_CHILD].clone();
        assert!(!witness.legacy_excluded_request_id_hashes.is_empty());
        // Select just the quiet member again without changing its bytes,
        // reduction, interpretation scope or prior census record.
        index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let (mut index, _, mode) = run(index);
        assert_eq!(mode, Some(ReadMode::Unchanged));
        assert!(cache
            .retained_checkpoint(&key)
            .expect("the quiet member's Unchanged read must retain its native reduction")
            .audit_debt()
            .is_none());
        assert!(!index
            .claude_request_census
            .get(&key)
            .unwrap()
            .unverified_for_test());
        let saved = dir.join("index.json");
        index.save(&saved).unwrap();
        let mut index = ScanIndex::load(&saved).unwrap();
        assert!(!index
            .claude_request_census
            .get(&key)
            .unwrap()
            .unverified_for_test());
        // Exclusion-list state is pass-local, loaded independently of the index.
        index.claude_reemission_exclusions = ReemissionExclusions::parse(
            if paused {
                "invalid".to_string()
            } else {
                format!(
                    "{}\n{}",
                    request_hash(LEGACY_PARENT),
                    request_hash(LEGACY_CHILD)
                )
            }
            .as_bytes(),
        );
        let mut later = raw
            .iter()
            .filter(|item| item.source_session_id == LEGACY_CHILD)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(later.len(), 1, "quiet sibling has no current native body");
        apply_claude_reported_usage_with_identity(
            &mut later,
            &api,
            &trace,
            &mut index,
            false,
            LEGACY_WINDOW,
            None,
        );
        assert_eq!(index.claude_usage_family_witnesses[LEGACY_CHILD], witness);
        assert_eq!(
            later[0].usage_accounting_contract,
            expected.usage_accounting_contract
        );
        assert_eq!(later[0].model_usage, expected.model_usage);
        assert_eq!(later[0].cost, expected.cost);
        assert_eq!(later[0].input_tokens, expected.input_tokens);
        assert_eq!(later[0].request_count, expected.request_count);
        // A downgraded off-page record reproduces the original money failure.
        let fingerprint = index
            .claude_request_census
            .get(&key)
            .unwrap()
            .fingerprint_hex_for_test();
        record_claude_request_census(
            &mut index,
            ClaudeRequestCensusParse {
                path: &quiet_path,
                index_key: &key,
                source_file_fingerprint: &fingerprint,
                census_window_end: LEGACY_WINDOW,
                complete: true,
                lossy: false,
                source_verified: false,
                unchanged_source: false,
                itemless_request_hashes: vec![],
                opened_birth: None,
                modified_unix_seconds: 0,
            },
            &[],
        );
        let mut downgraded = raw
            .iter()
            .filter(|item| item.source_session_id == LEGACY_CHILD)
            .cloned()
            .collect::<Vec<_>>();
        apply_claude_reported_usage_with_identity(
            &mut downgraded,
            &api,
            &trace,
            &mut index,
            false,
            LEGACY_WINDOW,
            None,
        );
        assert!(downgraded[0].usage_accounting_contract.is_none());
        assert_eq!(
            downgraded[0].input_tokens, 926,
            "native money counts the copied prefix"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

/// Exclusions the owned-request accounting cannot prove are never subtracted
/// blindly, and an excluded request is never tagged. Each skewed item is
/// driven through the real reported rebuild (as the pass's call site feeds
/// it); every refused item keeps today's bytes.
#[test]
fn legacy_exclusion_skew_never_tags_or_borrows_the_parent() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    // Two telemetry-only requests: the 0.1.172 count guard (4 != 3) is
    // negative, so only exact owned accounting could admit the child.
    let (dir, mut items, api, trace, mut index) = legacy_fork_fixture(2);
    let raw_child = items[1].clone();
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let _ = apply_claude_reported_usage_with_identity(
        &mut items,
        &api,
        &trace,
        &mut index,
        true,
        LEGACY_WINDOW,
        Some(&evidence),
    );
    let reported_child = items.remove(1);
    // The ledger's rows for the child, in its request-id order.
    let mut rows = api.evidence[LEGACY_CHILD].clone();
    rows.sort_by(|a, b| a.request_id.cmp(&b.request_id));
    let rebuild = |excluded: &BTreeSet<String>| {
        let mut item = raw_child.clone();
        let mut sink = identity::RequestSink::for_item(&evidence, &item, usize::MAX)
            .unwrap()
            .excluding(&item, excluded);
        rebuild_claude_reported_usage(&mut item, &rows, excluded, Some(&mut sink)).then(|| {
            item.usage_accounting_contract =
                Some("session_exclusive_reported_usage:v1".to_string());
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
            (item, sink.finish())
        })
    };
    let refused = |item: SnapshotItem, grouping: identity::Grouping, case: &str| {
        let untouched = serde_json::to_vec(&item).unwrap();
        let groupings = BTreeMap::from([(item.source_session_id.clone(), grouping)]);
        let mut batch = vec![item];
        let outcome = identity::apply_scan(&mut batch, &evidence, groupings);
        assert_eq!(outcome.ineligible, 1, "{case}: {outcome:?}");
        assert_eq!(serde_json::to_vec(&batch[0]).unwrap(), untouched, "{case}");
    };
    let exact = BTreeSet::from([request_hash("req_shared")]);

    // The call site's rebuild reproduces the pass's reported child, and its
    // grouping is eligible by owned accounting alone.
    let (item, grouping) = rebuild(&exact).expect("exact exclusion rebuilds");
    assert_eq!(item.request_count, reported_child.request_count);
    assert_eq!(item.input_tokens, reported_child.input_tokens);
    assert_eq!(
        serde_json::to_value(&item.usage_buckets).unwrap(),
        serde_json::to_value(&reported_child.usage_buckets).unwrap()
    );
    assert!(grouping.owned_reported_requests(&item));
    assert!(claude_snapshot_request_id_hashes(&item).is_none());

    // Missing exclusion: the prefix would be the child's own, but it has no
    // row of the child's, so there is no reported body to tag.
    assert!(rebuild(&BTreeSet::new()).is_none(), "missing exclusion");
    // Excess exclusions naming a request the child does own, or every one.
    let owned_excluded = BTreeSet::from([request_hash("req_shared"), request_hash("req_child")]);
    assert!(rebuild(&owned_excluded).is_none(), "excluded own request");
    let all = ["req_shared", "req_child", "req_child_2"]
        .map(request_hash)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert!(rebuild(&all).is_none(), "nothing owned");

    // A non-member exclusion is not one of the child's requests: the count
    // the rebuild made cannot be reconciled by subtracting it.
    let nonmember = BTreeSet::from([request_hash("req_shared"), request_hash("req_elsewhere")]);
    let (item, grouping) = rebuild(&nonmember).expect("non-member rebuilds");
    assert!(!grouping.owned_reported_requests(&item));
    assert!(!grouping.reported_requests_admissible(&item));
    refused(item, grouping, "non-member exclusion");

    // Count and membership skew against an exact grouping.
    let (mut item, grouping) = rebuild(&exact).unwrap();
    item.request_count += 1;
    refused(item, grouping, "count mismatch");
    let (mut item, grouping) = rebuild(&exact).unwrap();
    item.claude_usage_request_ids
        .insert("req_unadmitted".into());
    // One unadmitted id makes the count coincide (4 == 4): the 0.1.172 guard
    // still admits that, exactly as it did, with only the rebuild's own rows.
    assert!(!grouping.owned_reported_requests(&item));
    assert!(grouping.reported_requests_admissible(&item));
    item.claude_usage_request_ids
        .insert("req_unadmitted_2".into());
    refused(item, grouping, "unadmitted transcript requests");

    // A grouping that admitted the excluded prefix (as a regressed rebuild
    // would) is refused even where the 0.1.172 count guard is positive: the
    // parent's request never tags the child, nor lends it the parent's login.
    let mut item = raw_child.clone();
    item.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".to_string());
    let mut sink = identity::RequestSink::for_item(&evidence, &item, usize::MAX)
        .unwrap()
        .excluding(&item, &exact);
    for (request_id, occurrence) in &raw_child.claude_usage_occurrences {
        let (row_key, _, _) = build_row_identity(
            occurrence.model.as_deref().unwrap(),
            &occurrence.selector,
            occurrence.reasoning_effort.as_deref(),
        );
        let mut usage = occurrence.usage.clone();
        usage.request_count = 1;
        sink.add(
            &item,
            identity::Request {
                request_id,
                occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
                timestamp: occurrence.timestamp.as_deref().unwrap(),
                bucket_start: "2026-08-02T07:00:00Z",
                row_key: &row_key,
                usage: &usage,
            },
        );
    }
    let grouping = sink.finish();
    assert!(claude_snapshot_request_id_hashes(&item).is_some());
    assert!(!grouping.reported_requests_admissible(&item));
    refused(item, grouping, "excluded request admitted");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unreadable_sidecars_refuse_and_unqualified_items_keep_todays_bytes() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, _root, items) = claude_account_family_fixture();
    let (api, trace) = reports(Vec::new(), Vec::new());
    let unreadable = ScanEvidence::new(&api, &trace, root_set(), None);
    let mut refused = items.clone();
    let outcome = identity::apply_scan(&mut refused, &unreadable, BTreeMap::new());
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
    let outcome = identity::apply_scan(&mut unqualified, &unreadable, BTreeMap::new());
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

// --- Review regressions ---------------------------------------------------------

#[test]
fn transcript_bases_need_the_original_clock() {
    let (api, trace) = reports(Vec::new(), Vec::new());
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let mut carried = facts("req_old", Some(999_000), MarkerVerdict::Trusted(D64));
    carried.event_clock_complete = false;
    assert_eq!(
        identity::classify(&evidence, &carried),
        RequestIdentity::Refused(Refusal::BadClock)
    );
    let unstamped = facts("req_old", None, MarkerVerdict::Trusted(D64));
    assert_eq!(
        identity::classify(&evidence, &unstamped),
        RequestIdentity::Refused(Refusal::BadClock)
    );
    // Without any transcript evidence the request is simply missing.
    let mut plain = facts("req_old", None, MarkerVerdict::None);
    plain.event_clock_complete = false;
    assert_eq!(
        identity::classify(&evidence, &plain),
        RequestIdentity::Missing
    );
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
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    assert!(evidence.memberships.is_empty());
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_forged", Some(900_000), MarkerVerdict::None)
        ),
        RequestIdentity::Refused(Refusal::InvalidEvidence)
    );
    assert_eq!(
        identity::classify(
            &evidence,
            &facts("req_login", Some(900_000), MarkerVerdict::Trusted(&org))
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
    assert!(crate::claude_local_otel::claude_sidecars_absent(
        &support, ROOT
    ));
    let digest = format!("{:x}", Sha256::digest(ROOT.as_bytes()));
    let stores = fs::read_dir(&support)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(stores, 0);
    // A directory where the trace sidecar should be is a failure, not absence.
    let trace_dir = crate::claude_local_otel::claude_trace_ownership_evidence_dir(&support);
    fs::create_dir_all(trace_dir.join(format!("{digest}.jsonl"))).unwrap();
    assert!(!crate::claude_local_otel::claude_sidecars_absent(
        &support, ROOT
    ));
    let _ = fs::remove_dir_all(support);
}

/// A contract-5 body tagged from four requests (`mixed`: two logins; else all
/// login A), with the given creator evidence, and its scan-local admission.
fn bound_case(
    mixed: bool,
    creator: Option<&str>,
) -> (
    PathBuf,
    Vec<SnapshotItem>,
    claude_request_accounts::MixedUploads,
) {
    let (dir, root, mut items) = claude_account_family_fixture();
    items.truncate(1);
    items[0].session_account_evidence = Some(SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: creator.map(str::to_string),
        provider_workspace_hash: creator.map(|_| "d".repeat(64)),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some(if creator.is_some() {
            "complete"
        } else {
            "missing"
        }),
        source_created_at: None,
    });
    let api = (1..=4)
        .map(|n| {
            let mut row = complete_api_row(&root, &format!("req_{n}"), n, 10, 10, 0);
            if mixed && n > 2 {
                row.account_identifier_hash = Some("b".repeat(64));
            }
            signed(row)
        })
        .collect::<Vec<_>>();
    let trace = (1..=4)
        .map(|n| complete_trace_row(&root, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    let (api, trace) = reports(api, trace);
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let outcome = identity::apply_scan(&mut items, &evidence, BTreeMap::new());
    assert_eq!(outcome.sent, 1, "{outcome:?}");
    let row = &items[0].usage_buckets[0].model_usage[0];
    if mixed {
        assert!(row.identity_parts.is_some());
    } else {
        assert!(row.identity_parts.is_none());
        assert_eq!(row.account_identifier_hash.as_deref(), Some(OWNER_A));
    }
    let mut admitted = claude_request_accounts::MixedUploads::default();
    admitted.admit_request_identity(&items[0]);
    (dir, items, admitted)
}

/// Binds against retained owner A on "machine"; returns (deferred, bindings
/// after, rows unchanged).
fn bind_owner_a(
    items: &mut [SnapshotItem],
    capability: &claude_request_accounts::MixedUploads,
    bound: bool,
    machine: &str,
) -> (bool, BTreeMap<String, SessionAccountBinding>, bool) {
    let mut index = ScanIndex::default();
    if bound {
        index.session_account_bindings.insert(
            sha256_hex(&["session_owner:v1", "machine", &items[0].source_session_id]),
            SessionAccountBinding {
                account_identifier_hash: OWNER_A.to_string(),
                workspace_identifier_hash: None,
            },
        );
    }
    let before = index.session_account_bindings.clone();
    let rows = serde_json::to_vec(items).unwrap();
    let deferred = index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        machine,
        items,
        &[],
        capability,
    );
    assert_eq!(
        index.session_account_bindings, before,
        "the owner map never changes"
    );
    (
        !deferred.is_empty(),
        index.session_account_bindings,
        serde_json::to_vec(items).unwrap() == rows,
    )
}

/// SESSION ruling 3: a bound session admits this scan's exact contract-5 body
/// only when creator proof is absent or names the retained owner, for mixed
/// AND single-identity bodies (including all-A rows that would take today's
/// matching-owner shortcut); the owner and the rows are never rewritten, and
/// nothing else obtains the exception.
#[test]
fn bound_sessions_admit_contract5_only_with_absent_or_matching_creator() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let login_b = "b".repeat(64);
    for mixed in [true, false] {
        for (creator, admitted) in [
            (None, true),
            (Some(OWNER_A), true),
            (Some(login_b.as_str()), false),
        ] {
            let (dir, mut items, capability) = bound_case(mixed, creator);
            let (deferred, _, rows_unchanged) =
                bind_owner_a(&mut items, &capability, true, "machine");
            assert_eq!(deferred, !admitted, "mixed={mixed} creator={creator:?}");
            assert!(
                rows_unchanged,
                "creator metadata never rewrites request identities"
            );
            let _ = fs::remove_dir_all(dir);
        }
    }

    // Everything below starts from an otherwise admissible all-A body.
    let (dir, items, capability) = bound_case(false, None);
    let none = claude_request_accounts::MixedUploads::default();
    let defers = |mut items: Vec<SnapshotItem>, capability| {
        bind_owner_a(&mut items, capability, true, "machine").0
    };
    assert!(defers(items.clone(), &none), "no or restarted capability");
    let mut changed = items.clone();
    changed[0].input_tokens += 1;
    assert!(defers(changed, &capability), "body changed after admission");
    let mut changed = items.clone();
    changed[0].usage_buckets[0].model_usage[0].evidence_ref = Some(1);
    assert!(defers(changed, &capability), "evidence ref changed");
    let mut changed = items.clone();
    changed[0]
        .session_account_evidence
        .as_mut()
        .unwrap()
        .account_identifier_hash = Some(OWNER_A.to_string());
    assert!(
        defers(changed, &capability),
        "creator changed after admission"
    );
    let mut other = items.clone();
    other[0].source_session_id = format!("{}_agent-a4d1585d310070d0f", other[0].source_session_id);
    assert!(defers(other, &capability), "another session or child");
    let mut forged = items.clone();
    forged[0].provenance.collector = identity::COLLECTOR.to_string();
    forged[0].request_evidence.clear();
    for row in forged[0]
        .usage_buckets
        .iter_mut()
        .flat_map(|b| b.model_usage.iter_mut())
    {
        row.evidence_ref = None;
    }
    assert!(defers(forged, &capability), "collector-only body");
    // Unbound (or bound on another machine): never acquires an owner here.
    for machine in ["machine", "other-machine"] {
        let mut unbound = items.clone();
        let bound = machine != "machine";
        let (deferred, bindings, _) = bind_owner_a(&mut unbound, &capability, bound, machine);
        assert!(!deferred);
        assert_eq!(
            bindings.len(),
            usize::from(bound),
            "{machine}: no owner acquired"
        );
    }
    let _ = fs::remove_dir_all(dir);

    // Mixed: changed parts after admission lose the exception.
    let (dir, mut items, capability) = bound_case(true, None);
    let parts = items[0].usage_buckets[0].model_usage[0]
        .identity_parts
        .as_mut()
        .unwrap();
    parts[0].input_tokens += 1;
    parts[1].input_tokens -= 1;
    assert!(
        bind_owner_a(&mut items, &capability, true, "machine").0,
        "parts changed"
    );
    let _ = fs::remove_dir_all(dir);
}

// --- transcript_email over the status-coverage feed --------------------------

/// Qualified status samples of `(login, org)` every cadence over `[from, to]`
/// for `home`, after a pass that reported `home` registered.
fn coverage(
    home: crate::claude_status_coverage::HomeKey,
    login: &str,
    org: &str,
    from: u64,
    to: u64,
) -> crate::claude_status_coverage::Ledger {
    let mut ledger = crate::claude_status_coverage::Ledger::default();
    let mut at = from;
    while at <= to {
        ledger.observe_at(
            home,
            [1; 32],
            Some(at),
            crate::claude_status_coverage::Observation::Qualified { login, org },
        );
        at += crate::claude_status_coverage::CADENCE_SECONDS;
    }
    // Registration has been known since the first sample's pass.
    ledger.retain(BTreeSet::from([home]), Some(from));
    ledger
}

// Released builds capture contract 5 for Claude Code always (no cohort
// token) and keep `transcript_email` and its feed compiled out, and
// `transcript_sole_login` suppressed independently of the email gate.
const _: () = assert!(
    identity::captures(SnapshotSource::ClaudeCode)
        && !identity::TRANSCRIPT_EMAIL_ENABLED
        && !identity::TRANSCRIPT_SOLE_LOGIN_ENABLED
);

#[test]
fn transcript_email_never_binds_and_refuses_unqualified_coverage() {
    use crate::claude_status_coverage::{home_key, Ledger, Observation, CADENCE_SECONDS};
    let org_e: &'static str = "e".repeat(64).leak();
    let org_f: &'static str = "f".repeat(64).leak();
    let home = home_key(Path::new("/synthetic/slot"));
    let other = home_key(Path::new("/synthetic/other"));
    let default_home = home_key(&crate::agent_status::home_dir().join(".claude"));
    let mut with_org = complete_api_row(ROOT, "req_org", 1, 10, 1, 0);
    with_org.request_identity = Some(org_identity(&"d".repeat(64)));
    let (api, trace) = reports(
        vec![signed(with_org)],
        vec![complete_trace_row(ROOT, "req_org", "")],
    );
    let with = |ledger: Option<Ledger>| {
        ScanEvidence::new(&api, &trace, BTreeSet::new(), None).with_status_coverage(ledger)
    };
    let request = |start: Option<u64>,
                   at: u64,
                   home: Option<&crate::claude_status_coverage::HomeKey>,
                   org: &'static str| {
        let mut request = facts("req_old", Some(at), MarkerVerdict::Trusted(org));
        request.email_home = home.map(|home| -> &'static _ { Box::leak(Box::new(*home)) });
        request.session_start_unix_seconds = start;
        request
    };
    let org_only = |org: &str| {
        RequestIdentity::Tagged(AuthorityKey {
            login: None,
            org: Some(org.to_string()),
            basis: identity::TRANSCRIPT_ORG,
        })
    };
    let refused = RequestIdentity::Refused;
    // LOGIN_A/org e sampled every cadence over [998_000, 1_000_100]. The slot
    // login is never selected: samples prove no continuity and the email is
    // never joined to a login.
    let sampled = with(Some(coverage(home, LOGIN_A, org_e, 998_000, 1_000_100)));
    let start = 998_300;
    let classify = |evidence: &ScanEvidence<'_>, facts: RequestFacts<'_>| {
        let identity = identity::classify(evidence, &facts);
        assert!(
            !matches!(&identity, RequestIdentity::Tagged(key) if key.login.is_some()),
            "an email never binds a login: {identity:?}"
        );
        identity
    };
    for (case, facts, expected) in [
        (
            "samples span the window (unseen A→B→A possible)",
            request(Some(start), 999_000, Some(&home), org_e),
            refused(Refusal::CoverageUnqualified),
        ),
        (
            "marker org differs from the sampled org",
            request(Some(start), 999_000, Some(&home), org_f),
            refused(Refusal::ContradictoryOrg),
        ),
        (
            "request after the last sample",
            request(Some(start), 1_000_101, Some(&home), org_e),
            refused(Refusal::CoverageUnavailable),
        ),
        (
            "window starts before the first sample",
            request(Some(start - 1), 999_000, Some(&home), org_e),
            refused(Refusal::CoverageUnavailable),
        ),
        (
            "unknown session start",
            request(None, 999_000, Some(&home), org_e),
            refused(Refusal::CoverageUnavailable),
        ),
        // Not applicable: the independently valid org-only meaning stands.
        (
            "no unchanged email before the request",
            request(Some(start), 999_000, None, org_e),
            org_only(org_e),
        ),
        (
            "unregistered folder",
            request(Some(start), 999_000, Some(&other), org_e),
            org_only(org_e),
        ),
        (
            "shared default folder",
            request(Some(start), 999_000, Some(&default_home), org_e),
            org_only(org_e),
        ),
    ] {
        assert_eq!(classify(&sampled, facts), expected, "{case}");
    }
    let mut desktop = request(Some(start), 999_000, Some(&home), org_e);
    desktop.desktop = true;
    assert_eq!(classify(&sampled, desktop), org_only(org_e), "Desktop");

    // A within-cadence sampled A→B→A conflicts.
    let mut switched = coverage(home, LOGIN_A, org_e, 998_000, 998_600);
    for (at, login) in [(998_900, OWNER_A), (999_200, LOGIN_A), (999_500, LOGIN_A)] {
        switched.observe_at(
            home,
            [1; 32],
            Some(at),
            Observation::Qualified { login, org: org_e },
        );
    }
    assert_eq!(
        classify(
            &with(Some(switched)),
            request(Some(start), 999_000, Some(&home), org_e)
        ),
        refused(Refusal::ContradictoryOrg)
    );
    // Enabled-feed failures refuse; none falls back to org-only.
    let mut gapped = coverage(home, LOGIN_A, org_e, 998_000, 998_600);
    for at in [999_201, 999_500, 999_800] {
        gapped.observe_at(
            home,
            [1; 32],
            Some(at),
            Observation::Qualified {
                login: LOGIN_A,
                org: org_e,
            },
        );
    }
    let mut unavailable = coverage(home, LOGIN_A, org_e, 998_000, 1_000_100);
    unavailable.observe_at(home, [1; 32], Some(999_100), Observation::Unavailable);
    for at in (999_400..=1_000_100).step_by(CADENCE_SECONDS as usize) {
        unavailable.observe_at(
            home,
            [1; 32],
            Some(at),
            Observation::Qualified {
                login: LOGIN_A,
                org: org_e,
            },
        );
    }
    let mut restarted = Ledger::default();
    for at in (998_000..=1_000_100).step_by(CADENCE_SECONDS as usize) {
        restarted.observe_at(
            home,
            [1; 32],
            Some(at),
            Observation::Qualified {
                login: LOGIN_A,
                org: org_e,
            },
        );
    }
    let mut evicted = coverage(home, LOGIN_A, org_e, 998_000, 998_600);
    for n in 0..crate::claude_status_coverage::MAX_SEGMENTS_PER_SLOT as u64 {
        evicted.observe_at(
            home,
            [1; 32],
            Some(1_100_000 + n * 1_000),
            Observation::Qualified {
                login: LOGIN_A,
                org: org_e,
            },
        );
    }
    for (case, ledger) in [
        ("gap of more than two cadences", Some(gapped)),
        ("unavailable sample inside the window", Some(unavailable)),
        ("no completed pass since restart", Some(restarted)),
        ("window evicted", Some(evicted)),
        ("feed failed or absent", None),
    ] {
        assert_eq!(
            classify(
                &with(ledger),
                request(Some(start), 999_000, Some(&home), org_e)
            ),
            refused(Refusal::CoverageUnavailable),
            "{case}"
        );
    }
    // A carried clock still refuses for the clock; telemetry still wins.
    let mut carried = request(Some(start), 999_000, Some(&home), org_e);
    carried.event_clock_complete = false;
    assert_eq!(classify(&sampled, carried), refused(Refusal::BadClock));
    let mut telemetry = request(Some(start), 999_000, Some(&home), org_e);
    telemetry.request_id = "req_org";
    assert_eq!(
        identity::classify(&sampled, &telemetry),
        RequestIdentity::Tagged(AuthorityKey {
            login: Some(OWNER_A.to_string()),
            org: Some("d".repeat(64)),
            basis: identity::TELEMETRY,
        })
    );
}

#[test]
fn status_pairings_establish_marker_org_membership_for_the_telemetry_login() {
    let org_e = "e".repeat(64);
    let home = crate::claude_status_coverage::home_key(Path::new("/synthetic/slot"));
    let login_only = complete_api_row(ROOT, "req_login", 2, 10, 1, 0);
    let (api, trace) = reports(
        vec![signed(login_only)],
        vec![complete_trace_row(ROOT, "req_login", "")],
    );
    let request = facts("req_login", Some(999_000), MarkerVerdict::Trusted(&org_e));
    let tagged = |org: Option<&str>| {
        RequestIdentity::Tagged(AuthorityKey {
            login: Some(OWNER_A.to_string()),
            org: org.map(str::to_string),
            basis: identity::TELEMETRY_LOGIN,
        })
    };
    // Without existing evidence the marker org is not established (§2a.12).
    let plain = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    assert_eq!(identity::classify(&plain, &request), tagged(None));
    // The status pass's qualified (login, org) pairing establishes it (§2a.12(b)),
    // even from a single observation: membership is not a coverage claim.
    let paired = ScanEvidence::new(&api, &trace, BTreeSet::new(), None)
        .with_status_coverage(Some(coverage(home, OWNER_A, &org_e, 1, 1)));
    assert_eq!(identity::classify(&paired, &request), tagged(Some(&org_e)));
    // Another login's pairing establishes nothing for this one.
    let foreign = ScanEvidence::new(&api, &trace, BTreeSet::new(), None)
        .with_status_coverage(Some(coverage(home, LOGIN_A, &org_e, 1, 1)));
    assert_eq!(identity::classify(&foreign, &request), tagged(None));
}

/// One synthetic session in a slot folder: an arbitrary recorded email (before
/// or after `req_1`, optionally switched), a credential org marker and `req_1`.
fn email_session(email_first: bool, flip: bool) -> Vec<Value> {
    let mut lines = Vec::new();
    // An arbitrary email: nothing joins it to the slot's sampled login.
    let context_line = json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment",
        "sessionId": ROOT, "attachment": {"type": "session_context",
        "context": {"userEmail": "someone-else@example.invalid"}}});
    if email_first {
        lines.push(context_line.clone());
    }
    if flip {
        lines.push(
            json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment",
            "sessionId": ROOT, "attachment": {"type": "session_context",
            "context": {"userEmail": "other@example.invalid"}}}),
        );
    }
    lines.push(
        json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment", "sessionId": ROOT,
        "attachment": {"type": "credential_org", "organizationUuid": ORG_1}}),
    );
    lines.push(
        json!({"timestamp": "2026-08-02T07:00:01Z", "type": "assistant", "sessionId": ROOT,
        "requestId": "req_1", "message": {"id": "m1", "model": "claude-haiku-4-5",
        "usage": {"input_tokens": 10, "output_tokens": 1}}}),
    );
    if !email_first {
        lines.push(context_line);
    }
    lines
}

fn parse_session(folder: &Path, lines: &[Value]) -> Vec<SnapshotItem> {
    let project = folder.join("projects").join("-synthetic-repo");
    fs::create_dir_all(&project).unwrap();
    let path = project.join(format!("{ROOT}.jsonl"));
    fs::write(
        &path,
        lines
            .iter()
            .map(|line| line.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", "fp".into()).unwrap()
}

#[test]
fn unmatched_email_in_a_registered_folder_is_refused_end_to_end_with_usage_conserved() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-request-identity-email");
    let slot = dir.join("slot");
    let home = crate::claude_status_coverage::home_key(&slot);
    let email_home = |items: &[SnapshotItem]| {
        let item = &items[0];
        let sequence = item.claude_usage_occurrences["req_1"].sequence;
        item.claude_org_markers
            .as_deref()
            .and_then(|markers| markers.email_home(sequence))
            .copied()
    };
    let items = parse_session(&slot, &email_session(true, false));
    assert_eq!(email_home(&items), Some(home));
    let wire = serde_json::to_string(&items[0]).unwrap();
    assert!(!wire.contains("example.invalid"), "no email on the item");
    assert_eq!(
        email_home(&parse_session(&slot, &email_session(false, false))),
        None,
        "email after the request"
    );
    assert_eq!(
        email_home(&parse_session(&slot, &email_session(true, true))),
        None,
        "email switched before it"
    );

    // Slot samples LOGIN_A under the marker org over the whole window.
    let request_at = rfc3339_unix_seconds("2026-08-02T07:00:01Z").unwrap();
    let start_of = |items: &[SnapshotItem]| {
        rfc3339_unix_seconds(items[0].source_started_at.as_deref().unwrap()).unwrap()
    };
    let (api, trace) = reports(Vec::new(), Vec::new());
    let mut items = parse_session(&slot, &email_session(true, false));
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None).with_status_coverage(
        Some(coverage(
            home,
            LOGIN_A,
            &org_hash(ORG_1),
            start_of(&items) - 600,
            request_at + 300,
        )),
    );
    let before = items[0].clone();
    identity::apply_scan(&mut items, &evidence, BTreeMap::new());
    let item = &items[0];
    // Refused, not weakened: no login, no org-only evidence, a positive
    // refusal (which also blocks Desktop-pair fill), usage and money intact.
    assert!(item.request_identity_refusals >= 1);
    let text = serde_json::to_string(item).unwrap();
    assert!(!text.contains(LOGIN_A), "the slot login is never selected");
    assert!(item
        .request_evidence
        .iter()
        .all(|evidence| evidence.identity_basis != identity::TRANSCRIPT_ORG));
    assert_eq!(item.input_tokens, before.input_tokens);
    assert_eq!(item.output_tokens, before.output_tokens);
    assert_eq!(item.request_count, before.request_count);
    assert_eq!(item.cost, before.cost);
    let rows = |item: &SnapshotItem| {
        item.usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage)
            .map(|row| (row.request_count, row.input_tokens, row.cost_usd.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(rows(item), rows(&before));
    let home_hex = home
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    for absent in ["example.invalid", home_hex.as_str(), slot.to_str().unwrap()] {
        assert!(!text.contains(absent), "{absent}");
    }

    // Absent/disqualified email or an unregistered folder does not refuse,
    // but its transcript-only org is still withdrawn.
    for mut other in [
        parse_session(&slot, &email_session(false, false)),
        parse_session(&slot, &email_session(true, true)),
        parse_session(&dir.join("loose"), &email_session(true, false)),
    ] {
        identity::apply_scan(&mut other, &evidence, BTreeMap::new());
        assert!(other[0].request_evidence.is_empty());
        assert_eq!(other[0].request_identity_refusals, 0);
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn removed_slot_keeps_its_refusal_and_lost_registration_never_proves_absence() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::claude_status_coverage::{home_key, Ledger, Registration, MAX_LOST};
    let dir = temp_dir("claude-request-identity-removed-slot");
    let (slot, loose) = (dir.join("slot"), dir.join("loose"));
    let home = home_key(&slot);
    let org = org_hash(ORG_1);
    let request_at = rfc3339_unix_seconds("2026-08-02T07:00:01Z").unwrap();
    let start = rfc3339_unix_seconds(
        parse_session(&slot, &email_session(true, false))[0]
            .source_started_at
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let from = start - crate::claude_status_coverage::SESSION_LEAD_SECONDS;
    let (api, trace) = reports(Vec::new(), Vec::new());
    let scan = |folder: &Path, ledger: &Ledger| {
        let mut items = parse_session(folder, &email_session(true, false));
        let before = items[0].clone();
        let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None)
            .with_status_coverage(Some(ledger.clone()));
        identity::apply_scan(&mut items, &evidence, BTreeMap::new());
        (before, items.remove(0))
    };
    let rows = |item: &SnapshotItem| {
        item.usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage)
            .map(|row| (row.request_count, row.input_tokens, row.cost_usd.clone()))
            .collect::<Vec<_>>()
    };
    // Refused, never weakened: a positive refusal (which also blocks
    // Desktop-pair fill), no login, no org-only evidence, usage and money kept.
    let assert_refused = |case: &str, (before, item): (SnapshotItem, SnapshotItem)| {
        assert!(item.request_identity_refusals >= 1, "{case}");
        assert!(
            !serde_json::to_string(&item).unwrap().contains(LOGIN_A),
            "{case}"
        );
        assert!(
            item.request_evidence
                .iter()
                .all(|evidence| evidence.identity_basis != identity::TRANSCRIPT_ORG),
            "{case}"
        );
        assert_eq!(
            (item.input_tokens, item.output_tokens, item.request_count),
            (
                before.input_tokens,
                before.output_tokens,
                before.request_count
            ),
            "{case}"
        );
        assert_eq!(item.cost, before.cost, "{case}");
        assert_eq!(rows(&item), rows(&before), "{case}");
    };
    let assert_withdrawn = |case: &str, (_, item): (SnapshotItem, SnapshotItem)| {
        assert!(item.request_evidence.is_empty(), "{case}");
        assert_eq!(item.request_identity_refusals, 0, "{case}");
    };
    // Unit-level reason for the same request.
    let reason = |ledger: &Ledger, home: &crate::claude_status_coverage::HomeKey| {
        let (api, trace) = reports(Vec::new(), Vec::new());
        let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None)
            .with_status_coverage(Some(ledger.clone()));
        let mut request = facts("req_1", Some(request_at), MarkerVerdict::Trusted(&org));
        request.email_home = Some(home);
        request.session_start_unix_seconds = Some(start);
        identity::classify(&evidence, &request)
    };

    // Registered and sampled: refused as unqualified.
    let mut ledger = coverage(home, LOGIN_A, &org, from - 300, request_at + 300);
    assert_eq!(
        reason(&ledger, &home),
        RequestIdentity::Refused(Refusal::CoverageUnqualified)
    );
    assert_refused("registered slot", scan(&slot, &ledger));
    assert_withdrawn("never-registered folder", scan(&loose, &ledger));

    // The slot is removed: its history is cleared, but the SAME request stays
    // refused instead of becoming org-only.
    ledger.retain(BTreeSet::new(), Some(request_at + 600));
    assert_eq!(ledger.pairings().count(), 0, "history cleared");
    assert_eq!(ledger.registration(&home, from), Registration::Unknown);
    assert_eq!(
        reason(&ledger, &home),
        RequestIdentity::Refused(Refusal::CoverageUnavailable)
    );
    assert_refused("removed slot", scan(&slot, &ledger));
    assert_withdrawn(
        "never-registered control after removal",
        scan(&loose, &ledger),
    );
    // Re-registered: no history, still refused; removed again: still lost.
    ledger.retain(BTreeSet::from([home]), Some(request_at + 900));
    assert_refused("re-registered slot", scan(&slot, &ledger));
    ledger.retain(BTreeSet::new(), Some(request_at + 1_200));
    assert_refused("removed again", scan(&slot, &ledger));

    // Restart: no pass yet, so neither folder is known.
    let restarted = Ledger::default();
    assert_refused("restart, no pass", scan(&slot, &restarted));
    assert_refused("restart, never-registered folder", scan(&loose, &restarted));
    // First pass after the request: an earlier removal may have been missed.
    let mut late = Ledger::default();
    late.retain(BTreeSet::new(), Some(request_at + 60));
    assert_refused(
        "registration known only after the window",
        scan(&slot, &late),
    );
    assert_refused(
        "loose folder before registration was known",
        scan(&loose, &late),
    );
    let mut undated = Ledger::default();
    undated.retain(BTreeSet::new(), None);
    assert_refused("registration start unknown", scan(&loose, &undated));

    // Lost knowledge evicted: more removals than the record holds make every
    // unregistered folder unknown, never proven absent.
    let mut churn = coverage(home, LOGIN_A, &org, from - 300, request_at + 300);
    churn.retain(BTreeSet::new(), Some(request_at + 600));
    for n in 0..MAX_LOST {
        let other = home_key(Path::new(&format!("/synthetic/churn/{n}")));
        churn.retain(BTreeSet::from([other]), Some(request_at + 600));
        churn.retain(BTreeSet::new(), Some(request_at + 600));
    }
    assert!(churn.retained_bytes() <= crate::claude_status_coverage::MAX_BYTES);
    assert_eq!(
        churn.registration(&home_key(&loose), from),
        Registration::Unknown
    );
    assert_refused("overflowed loss record, removed slot", scan(&slot, &churn));
    assert_refused("overflowed loss record, loose folder", scan(&loose, &churn));

    // Proven not-applicable controls keep org-only even after removal.
    let default_home = home_key(&crate::agent_status::home_dir().join(".claude"));
    let org_only = RequestIdentity::Tagged(AuthorityKey {
        login: None,
        org: Some(org.clone()),
        basis: identity::TRANSCRIPT_ORG,
    });
    assert_eq!(
        reason(&ledger, &default_home),
        org_only,
        "shared default folder"
    );
    let (api2, trace2) = reports(Vec::new(), Vec::new());
    let evidence = ScanEvidence::new(&api2, &trace2, BTreeSet::new(), None)
        .with_status_coverage(Some(ledger.clone()));
    let mut desktop = facts("req_1", Some(request_at), MarkerVerdict::Trusted(&org));
    desktop.email_home = Some(&home);
    desktop.session_start_unix_seconds = Some(start);
    desktop.desktop = true;
    assert_eq!(identity::classify(&evidence, &desktop), org_only, "Desktop");
    let _ = fs::remove_dir_all(dir);
}

// --- Cross-root ownership and settled transcript markers ----------------------

const OTHER_ROOT: &str = "2448b91b-a47d-4dcd-b6cc-61ad77541cb6";
const THIRD_ROOT: &str = "3558ca2c-b58e-4ede-87dd-72be88652dc7";

/// Telemetry and trace rows are keyed by trace root, so a fork or resume copy
/// under another root holds a request whose rows sit under the original root.
/// Those rows own the request: the copy never tags it from its own markers,
/// and rows under two other roots leave no single owner. A root's own rows
/// still decide its own requests.
#[test]
fn rows_under_another_root_own_the_request() {
    let mut api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let mut trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    for (root, request_ids) in [
        (ROOT, &["req_own", "req_both"][..]),
        (OTHER_ROOT, &["req_foreign", "req_both", "req_two"][..]),
        (THIRD_ROOT, &["req_two"][..]),
    ] {
        api_report.evidence.insert(
            root.to_string(),
            request_ids
                .iter()
                .enumerate()
                .map(|(n, id)| signed(complete_api_row(root, id, n as u64 + 1, 10, 1, 0)))
                .collect(),
        );
        trace_report.evidence.insert(
            root.to_string(),
            request_ids
                .iter()
                .map(|id| complete_trace_row(root, id, ""))
                .collect(),
        );
    }
    // A trace owner alone, with no telemetry row anywhere.
    trace_report
        .evidence
        .get_mut(OTHER_ROOT)
        .unwrap()
        .push(complete_trace_row(OTHER_ROOT, "req_traced", ""));
    let evidence = ScanEvidence::new(&api_report, &trace_report, BTreeSet::new(), None);
    let from = |root: &'static str, request_id: &'static str| {
        let mut request = facts(request_id, Some(900_000), MarkerVerdict::Trusted(D64));
        request.root = root;
        request.source_session_id = root;
        identity::classify(&evidence, &request)
    };
    let refused = RequestIdentity::Refused;
    // The copy under ROOT: its own markers never claim another root's request.
    assert_eq!(from(ROOT, "req_foreign"), refused(Refusal::ForeignOwner));
    assert_eq!(from(ROOT, "req_traced"), refused(Refusal::ForeignOwner));
    assert_eq!(
        from(ROOT, "req_two"),
        refused(Refusal::ConflictingDuplicate)
    );
    // Controls: each root's own rows decide its own requests, and a request
    // no root's rows name keeps the transcript bases.
    let login_only = RequestIdentity::Tagged(AuthorityKey {
        login: Some(OWNER_A.to_string()),
        org: None,
        basis: identity::TELEMETRY_LOGIN,
    });
    assert_eq!(from(ROOT, "req_own"), login_only);
    assert_eq!(from(ROOT, "req_both"), login_only);
    assert_eq!(from(OTHER_ROOT, "req_foreign"), login_only);
    assert_eq!(from(THIRD_ROOT, "req_two"), login_only);
    assert_eq!(
        from(ROOT, "req_unrowed"),
        RequestIdentity::Tagged(AuthorityKey {
            login: None,
            org: Some(D64.to_string()),
            basis: identity::TRANSCRIPT_ORG,
        })
    );
}

/// The open/settled result that D2 will supply cannot authorize copied
/// markers. Both production grouping routes must withdraw them, even before
/// D2 exists, on legacy/OFF and default state, and after index reload.
#[test]
fn copied_markers_are_withdrawn_on_both_paths_in_every_census_state() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::ClaudeDuplicateCensusCounts;
    let dir = temp_dir("claude-i1b-copied-markers");
    let org = org_hash(ORG_1);
    // A copied prefix can contain a perfectly valid marker and request id.
    // The current census may not have observed its other holder yet.
    // Keep one unchanged selector context so withdrawn marker usage and a
    // foreign-owner refusal must merge within the same bucket row.
    let mut lines = vec![
        json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment", "sessionId": ROOT,
        "attachment": {"type": "credential_org", "organizationUuid": ORG_1}}),
    ];
    for n in 1..=5 {
        lines.push(owned_response(
            &format!("req_{n}"),
            "2026-08-02T07:00:02Z",
            n * 10,
            n,
        ));
    }
    let mut paired = complete_api_row(ROOT, "req_3", 3, 30, 3, 0);
    paired.request_identity = Some(org_identity(&org));
    let (api, mut trace) = reports(
        vec![
            signed(complete_api_row(ROOT, "req_2", 2, 20, 2, 0)),
            signed(paired),
        ],
        vec![
            complete_trace_row(ROOT, "req_2", ""),
            complete_trace_row(ROOT, "req_3", ""),
        ],
    );
    trace.evidence.insert(
        OTHER_ROOT.to_string(),
        vec![complete_trace_row(OTHER_ROOT, "req_5", "")],
    );
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let open = ClaudeDuplicateCensusCounts {
        census_complete: true,
        coverage_complete: true,
        ..Default::default()
    };
    let clean = ScanIndex::default();
    let mut saved = clean.clone();
    saved.claude_duplicate_request_owners.insert(
        format!("{:x}", Sha256::digest(b"req_5")),
        BTreeSet::from([
            claude_duplicate_request_owner(ROOT, ROOT),
            claude_duplicate_request_owner(OTHER_ROOT, OTHER_ROOT),
        ]),
    );
    let restarted: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
    assert_eq!(
        restarted.claude_duplicate_request_owners,
        saved.claude_duplicate_request_owners
    );
    // There is deliberately no D2 switch in this prerequisite. Legacy/OFF
    // and future D2-open inputs reach the same unconditional boundary.
    for (state, index, census, compared) in [
        ("settled-open", &clean, open, true),
        (
            "legacy-off-closed",
            &clean,
            ClaudeDuplicateCensusCounts {
                fence_after: true,
                ..open
            },
            true,
        ),
        (
            "default-index",
            &clean,
            ClaudeDuplicateCensusCounts::default(),
            false,
        ),
        ("restart-open", &restarted, open, true),
    ] {
        let disposition = ClaudeUsageAuthorityDisposition {
            duplicate_census: census,
            transcript_ownership_complete: compared,
            ..Default::default()
        };
        let ownership = identity::TranscriptOwnership::after_census(index, &disposition);
        for reported in [false, true] {
            let mut item = parse_session(&dir, &lines).remove(0);
            let groupings = if reported {
                item.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".into());
                let mut sink =
                    identity::RequestSink::for_item(&evidence, &item, usize::MAX).unwrap();
                for (request_id, occurrence) in &item.claude_usage_occurrences {
                    let (row_key, _, _) = build_row_identity(
                        occurrence.model.as_deref().unwrap(),
                        &occurrence.selector,
                        occurrence.reasoning_effort.as_deref(),
                    );
                    let mut usage = occurrence.usage.clone();
                    usage.request_count = 1;
                    sink.add(
                        &item,
                        identity::Request {
                            request_id,
                            occurrence: Some((
                                occurrence.sequence,
                                occurrence.event_clock_complete,
                            )),
                            timestamp: occurrence.timestamp.as_deref().unwrap(),
                            bucket_start: "2026-08-02T07:00:00Z",
                            row_key: &row_key,
                            usage: &usage,
                        },
                    );
                }
                let grouping = sink.finish();
                assert!(grouping.owned_reported_requests(&item));
                BTreeMap::from([(item.source_session_id.clone(), grouping)])
            } else {
                BTreeMap::new()
            };
            let before = item.clone();
            let mut items = vec![item];
            let outcome =
                identity::apply_scan_with_ownership(&mut items, &evidence, groupings, &ownership);
            assert_eq!(outcome.sent, 1, "{state} reported={reported}: {outcome:?}");
            let item = &items[0];
            assert_usage_conserved(item, &before);
            assert_eq!(
                item.request_identity_refusals, 1,
                "the foreign-owner refusal survives"
            );
            assert_eq!(
                item.request_evidence
                    .iter()
                    .map(|e| (
                        e.identity_basis.as_str(),
                        e.provider_workspace_hash.as_deref()
                    ))
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    (identity::TELEMETRY, Some(org.as_str())),
                    (identity::TELEMETRY_LOGIN, None)
                ]),
                "{state} reported={reported}"
            );
            let parts = contributions_of(item).unwrap();
            let shares = |basis| {
                parts.iter().filter(|p| matches!(&p.identity, RequestIdentity::Tagged(key) if key.basis == basis)).collect::<Vec<_>>()
            };
            let login = shares(identity::TELEMETRY_LOGIN);
            assert_eq!(login.len(), 1);
            assert_eq!(
                login[0].identity,
                RequestIdentity::Tagged(AuthorityKey {
                    login: Some(OWNER_A.into()),
                    org: None,
                    basis: identity::TELEMETRY_LOGIN
                })
            );
            assert_eq!(
                (login[0].usage.request_count, login[0].usage.input_tokens),
                (1, 20)
            );
            let telemetry = shares(identity::TELEMETRY);
            assert_eq!(telemetry.len(), 1);
            assert_eq!(
                (
                    telemetry[0].usage.request_count,
                    telemetry[0].usage.input_tokens
                ),
                (1, 30)
            );
            let untagged = parts
                .iter()
                .filter(|p| !matches!(p.identity, RequestIdentity::Tagged(_)))
                .collect::<Vec<_>>();
            assert_eq!(
                untagged.len(),
                1,
                "withdrawn marker and refused usage merge"
            );
            assert_eq!(
                (
                    untagged[0].usage.request_count,
                    untagged[0].usage.input_tokens
                ),
                (3, 100)
            );
            // An already tagged re-emission stays byte-identical. It cannot
            // reclassify old marker evidence or add refusals a second time.
            let bytes = serde_json::to_vec(&items).unwrap();
            let again = identity::apply_scan_with_ownership(
                &mut items,
                &evidence,
                BTreeMap::new(),
                &ownership,
            );
            assert_eq!(again, identity::ScanOutcome::default());
            assert_eq!(serde_json::to_vec(&items).unwrap(), bytes);
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// Non-marker capture-ON bodies retain main's pre-withdrawal wire bytes.
/// The oracle reproduces tag_item at main 02cad8ab: build the RequestSink
/// grouping and apply it directly, which a settled pass did on that head.
#[test]
fn capture_on_non_marker_body_matches_main_before_withdrawal() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-i1b-non-marker-parity");
    let lines = vec![
        json!({"timestamp": "2026-08-02T07:00:00Z", "type": "attachment", "sessionId": ROOT,
            "attachment": {"type": "session_context", "context": {}}}),
        owned_response("req_1", "2026-08-02T07:00:01Z", 10, 1),
    ];
    let (api, trace) = reports(
        vec![signed(complete_api_row(ROOT, "req_1", 1, 10, 1, 0))],
        vec![complete_trace_row(ROOT, "req_1", "")],
    );
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let mut items = parse_session(&dir, &lines);
    assert!(items[0].claude_org_markers.is_some(), "capture ON");
    let mut main = items[0].clone();
    let occurrence = &main.claude_usage_occurrences["req_1"];
    let (row_key, _, _) = build_row_identity(
        occurrence.model.as_deref().unwrap(),
        &occurrence.selector,
        occurrence.reasoning_effort.as_deref(),
    );
    let mut usage = occurrence.usage.clone();
    usage.request_count = 1;
    let mut sink = identity::RequestSink::for_item(&evidence, &main, usize::MAX).unwrap();
    sink.add(
        &main,
        identity::Request {
            request_id: "req_1",
            occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
            timestamp: occurrence.timestamp.as_deref().unwrap(),
            bucket_start: "2026-08-02T07:00:00Z",
            row_key: &row_key,
            usage: &usage,
        },
    );
    assert!(matches!(
        identity::apply_grouped(&mut main, sink.finish()),
        Ok(Tagged::Sent { .. })
    ));
    assert_eq!(
        identity::apply_scan(&mut items, &evidence, BTreeMap::new()).sent,
        1
    );
    assert_eq!(
        serde_json::to_vec(&items[0]).unwrap(),
        serde_json::to_vec(&main).unwrap()
    );
    let _ = fs::remove_dir_all(dir);
}

// --- Zero-usage responses -----------------------------------------------------

/// One owned response of `ROOT` with its own request id.
fn owned_response(request_id: &str, timestamp: &str, input: u64, output: u64) -> Value {
    json!({"timestamp": timestamp, "type": "assistant", "sessionId": ROOT,
        "requestId": request_id, "message": {"id": format!("msg_{request_id}"),
        "model": "claude-haiku-4-5", "usage": {"input_tokens": input, "output_tokens": output}}})
}

/// An API-error record as Claude Code writes it: a synthetic assistant message
/// whose every usage field, cache included, is zero.
fn api_error_response(request_id: Option<&str>, timestamp: &str) -> Value {
    let mut line = json!({"timestamp": timestamp, "type": "assistant", "sessionId": ROOT,
        "isApiErrorMessage": true, "message": {"id": format!("msg_error_{timestamp}"),
        "model": "<synthetic>", "usage": {"input_tokens": 0, "output_tokens": 0,
        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0}}}});
    if let Some(request_id) = request_id {
        line["requestId"] = json!(request_id);
    }
    line
}

fn second(n: u64) -> String {
    format!("2026-08-02T07:00:{n:02}Z")
}

/// Three owned responses, each with telemetry under the default login.
fn owned_session() -> Vec<Value> {
    (1..=3)
        .map(|n| owned_response(&format!("req_{n}"), &second(n), 10, 10))
        .collect()
}

fn owned_session_reports() -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    reports(
        (1..=3)
            .map(|n| complete_api_row(ROOT, &format!("req_{n}"), n, 10, 10, 0))
            .collect(),
        (1..=3)
            .map(|n| complete_trace_row(ROOT, &format!("req_{n}"), ""))
            .collect(),
    )
}

fn tag_one(
    raw: &SnapshotItem,
    api: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) -> (identity::ScanOutcome, SnapshotItem) {
    let evidence = ScanEvidence::new(api, trace, BTreeSet::new(), None);
    let mut items = vec![raw.clone()];
    let outcome = identity::apply_scan(&mut items, &evidence, BTreeMap::new());
    (outcome, items.remove(0))
}

/// The tagged usage and identity a contract-5 body carries.
fn tagged_body(item: &SnapshotItem) -> (Value, Value, Value, u64) {
    (
        serde_json::to_value(&item.usage_buckets).unwrap(),
        serde_json::to_value(&item.model_usage).unwrap(),
        serde_json::to_value(&item.request_evidence).unwrap(),
        item.request_identity_refusals,
    )
}

/// A response whose usage is zero in every field, cache included, but which
/// carries a request id (an API error) adds no row, token or money. Appending
/// one keeps the session contract 5 with exactly the tagged usage it had: the
/// error is never counted, placed or classified, so even telemetry of its own
/// under another login claims nothing. Non-permit D1 and the parser's
/// request-id set keep today's behavior.
#[test]
fn zero_usage_api_error_with_request_id_keeps_contract5_and_claims_nothing() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-request-identity-zero-usage");
    let other_login = "b".repeat(64);
    let base = owned_session();
    let mut appended = base.clone();
    appended.push(api_error_response(Some("req_error"), &second(4)));
    let raw_before = parse_session(&dir, &base).remove(0);
    let raw_after = parse_session(&dir, &appended).remove(0);
    // The trigger: the parser keeps the error's id but counts no request.
    assert_eq!(raw_before.request_count, 3);
    assert_eq!(raw_after.request_count, 3);
    assert_eq!(raw_after.claude_usage_request_ids.len(), 4);
    assert!(raw_after.claude_usage_occurrences["req_error"]
        .usage
        .is_zero());
    assert!(claude_snapshot_request_id_hashes(&raw_before).is_some());
    assert!(claude_snapshot_request_id_hashes(&raw_after).is_none());
    assert_usage_conserved(&raw_after, &raw_before);

    let (api, trace) = owned_session_reports();
    let (mut claimed_api, mut claimed_trace) = owned_session_reports();
    let mut error_row = complete_api_row(ROOT, "req_error", 4, 0, 0, 0);
    error_row.account_identifier_hash = Some(other_login.clone());
    claimed_api
        .evidence
        .get_mut(ROOT)
        .unwrap()
        .push(signed(error_row));
    claimed_trace
        .evidence
        .get_mut(ROOT)
        .unwrap()
        .push(complete_trace_row(ROOT, "req_error", ""));

    let sent = identity::ScanOutcome {
        sent: 1,
        ..Default::default()
    };
    let (outcome, before) = tag_one(&raw_before, &api, &trace);
    assert_eq!(outcome, sent);
    assert_eq!(
        identity_shares(&before),
        (BTreeMap::from([(OWNER_A.to_string(), (3, 0))]), (0, 0))
    );
    for (api, trace) in [(&api, &trace), (&claimed_api, &claimed_trace)] {
        let (outcome, after) = tag_one(&raw_after, api, trace);
        assert_eq!(outcome, sent);
        assert_eq!(after.provenance.collector, identity::COLLECTOR);
        assert_usage_conserved(&after, &raw_after);
        assert_eq!(tagged_body(&after), tagged_body(&before));
        assert_eq!(after.request_identity_refusals, 0);
        assert!(!serde_json::to_string(&after)
            .unwrap()
            .contains(&other_login));
    }

    // Non-permit D1 keeps the plain request-id count guard.
    let d1 = |raw: &SnapshotItem| {
        let mut items = vec![raw.clone()];
        let coverage = claude_request_accounts::apply(&mut items, &api, &trace).coverage;
        (coverage, items.remove(0).provenance.collector)
    };
    assert_eq!(
        d1(&raw_before),
        (
            vec![claude_request_accounts::Coverage::Complete],
            claude_request_accounts::COMPLETE.to_string()
        )
    );
    assert_eq!(
        d1(&raw_after),
        (
            vec![claude_request_accounts::Coverage::MissingRequests],
            claude_request_accounts::UNKNOWN.to_string()
        )
    );
    let _ = fs::remove_dir_all(dir);
}

/// Zero-usage records the parser never counts as a request id keep today's
/// contract 5 unchanged: an error without a request id, and a response whose
/// early progressive record is all zero before its final usage.
#[test]
fn zero_usage_without_an_id_or_before_final_usage_keeps_todays_contract5() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-request-identity-zero-usage-unchanged");
    let (api, trace) = owned_session_reports();
    let base = owned_session();
    let (outcome, expected) = tag_one(&parse_session(&dir, &base).remove(0), &api, &trace);
    assert_eq!(outcome.sent, 1, "{outcome:?}");

    let mut without_id = base.clone();
    without_id.push(api_error_response(None, &second(4)));
    let mut progressive = base.clone();
    progressive.insert(2, owned_response("req_3", "2026-08-02T07:00:02.500Z", 0, 0));
    for (case, lines) in [("without id", without_id), ("progressive", progressive)] {
        let raw = parse_session(&dir, &lines).remove(0);
        assert_eq!(raw.request_count, 3, "{case}");
        assert_eq!(raw.claude_usage_request_ids.len(), 3, "{case}");
        assert!(
            raw.claude_usage_occurrences
                .values()
                .all(|occurrence| !occurrence.usage.is_zero()),
            "{case}"
        );
        assert!(claude_snapshot_request_id_hashes(&raw).is_some(), "{case}");
        let (outcome, tagged) = tag_one(&raw, &api, &trace);
        assert_eq!(outcome.sent, 1, "{case}: {outcome:?}");
        assert_usage_conserved(&tagged, &raw);
        assert_eq!(tagged_body(&tagged), tagged_body(&expected), "{case}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// A zero-usage record admits nothing else: with one present, nonzero usage
/// without its own request id, a nonzero request id held by two responses, a
/// multi-iteration response and a row the requests cannot reproduce each keep
/// the item on today's path with its bytes unchanged. The first two make the
/// plain request-id count coincide, which never admitted them either.
#[test]
fn zero_usage_record_never_admits_unowned_or_uncounted_usage() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-request-identity-zero-usage-negatives");
    let (api, trace) = owned_session_reports();
    let with_error = |extra: Option<Value>| {
        let mut lines = owned_session();
        lines.push(api_error_response(Some("req_error"), &second(4)));
        lines.extend(extra);
        parse_session(&dir, &lines).remove(0)
    };
    let without_id = json!({"timestamp": second(5), "type": "assistant", "sessionId": ROOT,
        "message": {"id": "msg_without_id", "model": "claude-haiku-4-5",
        "usage": {"input_tokens": 10, "output_tokens": 10}}});
    let mut duplicate = owned_response("req_2", &second(5), 10, 10);
    duplicate["message"]["id"] = json!("msg_duplicate");
    let mut iterations = owned_response("req_4", &second(5), 10, 10);
    iterations["message"]["usage"]["iterations"] =
        json!([{"input_tokens": 5, "output_tokens": 5}, {"input_tokens": 5, "output_tokens": 5}]);
    let mut unreproduced = with_error(None);
    unreproduced.usage_buckets[0].model_usage[0].request_count += 1;

    let coincident = [
        ("nonzero without id", with_error(Some(without_id))),
        ("nonzero duplicate id", with_error(Some(duplicate))),
    ];
    for (case, raw) in &coincident {
        assert_eq!(raw.request_count, 4, "{case}");
        assert!(claude_snapshot_request_id_hashes(raw).is_some(), "{case}");
    }
    let iterated = with_error(Some(iterations));
    assert!(!iterated.claude_context_curve_request_index_complete);
    for (case, raw) in coincident.into_iter().chain([
        ("multi-iteration response", iterated),
        ("row not reproduced", unreproduced),
    ]) {
        let untouched = serde_json::to_vec(&raw).unwrap();
        let (outcome, item) = tag_one(&raw, &api, &trace);
        assert_eq!(
            outcome,
            identity::ScanOutcome {
                ineligible: 1,
                ..Default::default()
            },
            "{case}"
        );
        assert_eq!(serde_json::to_vec(&item).unwrap(), untouched, "{case}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// A copied response whose telemetry sits under another root stays refused
/// and never lends that root's login, with or without a zero-usage record.
#[test]
fn zero_usage_record_keeps_a_foreign_owned_request_refused() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-request-identity-zero-usage-foreign");
    let foreign_login = "b".repeat(64);
    let mut api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let mut trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    let mut copied = complete_api_row(OTHER_ROOT, "req_copied", 1, 10, 10, 0);
    copied.account_identifier_hash = Some(foreign_login.clone());
    api_report
        .evidence
        .insert(OTHER_ROOT.to_string(), vec![signed(copied)]);
    trace_report.evidence.insert(
        OTHER_ROOT.to_string(),
        vec![complete_trace_row(OTHER_ROOT, "req_copied", "")],
    );
    api_report.evidence.insert(
        ROOT.to_string(),
        (2..=3)
            .map(|n| complete_api_row(ROOT, &format!("req_{n}"), n, 10, 10, 0))
            .collect(),
    );
    trace_report.evidence.insert(
        ROOT.to_string(),
        (2..=3)
            .map(|n| complete_trace_row(ROOT, &format!("req_{n}"), ""))
            .collect(),
    );
    let mut base = vec![owned_response("req_copied", &second(1), 10, 10)];
    base.extend((2..=3).map(|n| owned_response(&format!("req_{n}"), &second(n), 10, 10)));
    let mut appended = base.clone();
    appended.push(api_error_response(Some("req_error"), &second(4)));

    let mut bodies = Vec::new();
    for lines in [base, appended] {
        let raw = parse_session(&dir, &lines).remove(0);
        let (outcome, tagged) = tag_one(&raw, &api_report, &trace_report);
        assert_eq!(outcome.sent, 1, "{outcome:?}");
        assert_usage_conserved(&tagged, &raw);
        assert_eq!(
            identity_shares(&tagged),
            (BTreeMap::from([(OWNER_A.to_string(), (2, 0))]), (1, 0))
        );
        assert!(tagged.request_identity_refusals >= 1);
        assert!(!serde_json::to_string(&tagged)
            .unwrap()
            .contains(&foreign_login));
        bodies.push(tagged_body(&tagged));
    }
    assert_eq!(bodies[0], bodies[1]);
    let _ = fs::remove_dir_all(dir);
}

// Recent activity is independent of session-first origin and billing identity.
#[test]
fn desktop_recent_follows_each_request_entrypoint_and_governing_org() {
    let dir = temp_dir("desktop-recent-transitions");
    let mut lines = vec![marker(ORG_1)];
    for (n, entrypoint) in ["claude-desktop", "cli", "claude-desktop", "cli"]
        .iter()
        .enumerate()
    {
        if n == 2 {
            lines.push(marker(ORG_2));
        }
        lines.push(json!({"type": "assistant", "sessionId": ROOT,
            "timestamp": format!("2026-08-02T07:00:{:02}Z", 10 + n),
            "entrypoint": entrypoint, "requestId": format!("req_{n}"),
            "message": {"id": format!("msg_{n}"), "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10, "output_tokens": 1}}
        }));
    }
    let mut item = parse_session(&dir, &lines).remove(0);
    assert_eq!(
        item.origin.as_ref().unwrap().entrypoint.as_deref(),
        Some("claude-desktop")
    );
    item.session_account_evidence = Some(SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: Some(LOGIN_A.into()),
        provider_workspace_hash: Some(org_hash(ORG_1)),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some("complete"),
        source_created_at: Some("2026-08-02T07:00:00Z".into()),
    });
    let (api, trace) = reports(Vec::new(), Vec::new());
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let collect = |item: &SnapshotItem| {
        let mut sink = identity::RequestSink::for_item(&evidence, item, usize::MAX).unwrap();
        for (request_id, occurrence) in &item.claude_usage_occurrences {
            let (row_key, _, _) = build_row_identity(
                occurrence.model.as_deref().unwrap(),
                &occurrence.selector,
                occurrence.reasoning_effort.as_deref(),
            );
            sink.add(
                item,
                identity::Request {
                    request_id,
                    occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
                    timestamp: occurrence.timestamp.as_deref().unwrap(),
                    bucket_start: "2026-08-02T07:00:00Z",
                    row_key: &row_key,
                    usage: &occurrence.usage,
                },
            );
        }
        sink.finish()
    };
    let at =
        |seconds| OffsetDateTime::parse(&format!("2026-08-02T07:00:{seconds:02}Z"), &Rfc3339).ok();
    let grouping = collect(&item);
    assert_eq!(
        grouping.desktop_recent().at(LOGIN_A, &org_hash(ORG_1)),
        at(10)
    );
    assert_eq!(
        grouping.desktop_recent().at(LOGIN_A, &org_hash(ORG_2)),
        at(12)
    );
    // No native account, ambiguous/imported ownership, or old/future clocks cannot qualify.
    for disposition in ["missing", "conflict"] {
        let mut refused = item.clone();
        refused
            .session_account_evidence
            .as_mut()
            .unwrap()
            .identity_disposition = Some(disposition);
        assert_eq!(
            collect(&refused).desktop_recent(),
            &crate::desktop_recent::RecentActivity::default()
        );
    }
    let mut no_owner = item.clone();
    no_owner.session_account_evidence = None;
    assert_eq!(
        collect(&no_owner).desktop_recent(),
        &crate::desktop_recent::RecentActivity::default()
    );
    let mut expired = item.clone();
    expired.collected_at = "2026-08-02T07:16:00Z".into();
    assert_eq!(
        collect(&expired).desktop_recent(),
        &crate::desktop_recent::RecentActivity::default()
    );
    let mut future = item.clone();
    future.collected_at = "2026-08-02T07:00:00Z".into();
    assert_eq!(
        collect(&future).desktop_recent(),
        &crate::desktop_recent::RecentActivity::default()
    );
    // The account binding is copied exactly, never inferred from the org.
    let mut other = item.clone();
    other
        .session_account_evidence
        .as_mut()
        .unwrap()
        .account_identifier_hash = Some(D64.into());
    assert_eq!(
        collect(&other)
            .desktop_recent()
            .at(LOGIN_A, &org_hash(ORG_1)),
        None
    );
    assert_eq!(
        collect(&other).desktop_recent().at(D64, &org_hash(ORG_1)),
        at(10)
    );
    // Local bookkeeping cannot change serialized telemetry or diagnostics.
    let wire = serde_json::to_string(&item).unwrap();
    assert!(!wire.contains("desktop_request") && !wire.contains("desktop_recent"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn desktop_recent_cli_to_desktop_and_missing_entrypoint_fail_closed() {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    accumulator.claude_request_identity_capture = true;
    apply_claude_code_line(&marker(ORG_1), &mut accumulator);
    for (n, entrypoint) in [Some("cli"), Some("claude-desktop"), None]
        .iter()
        .enumerate()
    {
        if n == 1 {
            apply_claude_code_line(&marker(ORG_2), &mut accumulator);
        }
        let mut line = json!({"type": "assistant", "sessionId": ROOT,
            "timestamp": format!("2026-08-02T07:00:{n:02}Z"),
            "requestId": format!("req_{n}"), "message": {"id": format!("msg_{n}"),
            "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 1}}});
        if let Some(entrypoint) = entrypoint {
            line["entrypoint"] = json!(entrypoint);
        }
        apply_claude_code_line(&line, &mut accumulator);
    }
    accumulator.finalize_claude_responses();
    assert!(!accumulator.claude_usage_occurrences["req_0"].desktop_request);
    assert!(accumulator.claude_usage_occurrences["req_1"].desktop_request);
    assert!(!accumulator.claude_usage_occurrences["req_2"].desktop_request);
    assert_eq!(accumulator.origin.entrypoint.as_deref(), Some("cli"));
    let mut item = accumulator
        .into_items(
            Path::new("/synthetic/session.jsonl"),
            "2026-08-02T07:01:00Z",
            "fp".into(),
            None,
        )
        .remove(0);
    item.session_account_evidence = Some(SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: Some(LOGIN_A.into()),
        provider_workspace_hash: Some(org_hash(ORG_1)),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some("complete"),
        source_created_at: Some("2026-08-02T06:59:00Z".into()),
    });
    let (api, trace) = reports(Vec::new(), Vec::new());
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    let mut sink = identity::RequestSink::for_item(&evidence, &item, usize::MAX).unwrap();
    for (request_id, occurrence) in &item.claude_usage_occurrences {
        let (key, _, _) = build_row_identity(
            occurrence.model.as_deref().unwrap(),
            &occurrence.selector,
            None,
        );
        sink.add(
            &item,
            identity::Request {
                request_id,
                occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
                timestamp: occurrence.timestamp.as_deref().unwrap(),
                bucket_start: "2026-08-02T07:00:00Z",
                row_key: &key,
                usage: &occurrence.usage,
            },
        );
    }
    assert_eq!(
        sink.finish().desktop_recent().at(LOGIN_A, &org_hash(ORG_2)),
        OffsetDateTime::parse("2026-08-02T07:00:01Z", &Rfc3339).ok()
    );
}

/// Same order as the daemon: save native originals, apply request enrichment
/// (including its billing veto), rebuild/place requests, then publish the fold.
#[test]
fn desktop_recent_survives_same_account_org_switch_through_enrichment_and_both_folds() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("desktop-recent-enrichment");
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let first = now - time::Duration::seconds(60);
    let second = now - time::Duration::seconds(30);
    let stamp = |at: OffsetDateTime| at.format(&Rfc3339).unwrap();
    let account = "f2".repeat(32);
    let org1 = org_hash(ORG_1);
    let org2 = org_hash(ORG_2);
    let mut lines = vec![marker(ORG_1)];
    for (n, at) in [(1, first), (2, second)] {
        if n == 2 {
            lines.push(marker(ORG_2));
        }
        lines.push(json!({"type":"assistant", "sessionId":ROOT,
            "entrypoint":"claude-desktop", "timestamp":stamp(at),
            "requestId":format!("req_{n}"), "message":{"id":format!("msg_{n}"),
            "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}}));
    }
    let path = dir.join(format!("{ROOT}.jsonl"));
    fs::write(
        &path,
        lines
            .iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let mut item = parse_claude_code_jsonl_file(&path, &stamp(now), "fp".into())
        .unwrap()
        .remove(0);
    item.session_account_evidence = Some(SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: Some(account.clone()),
        provider_workspace_hash: Some(org1.clone()),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some("complete"),
        source_created_at: Some(stamp(first - time::Duration::seconds(1))),
    });
    let originals = BTreeMap::from([(
        ROOT.to_string(),
        item.session_account_evidence.clone().unwrap(),
    )]);
    let api_rows = [("req_1", &org1), ("req_2", &org2)]
        .into_iter()
        .enumerate()
        .map(|(i, (request, org))| {
            let mut row = complete_api_row(ROOT, request, i as u64 + 1, 10, 1, 0);
            row.account_identifier_hash = Some(account.clone());
            let mut identity = org_identity(org);
            identity.account.log_record_hash = Some(account.clone());
            row.request_identity = Some(identity);
            signed(row)
        })
        .collect::<Vec<_>>();
    let (api, trace) = reports(
        api_rows,
        vec![
            complete_trace_row(ROOT, "req_1", ""),
            complete_trace_row(ROOT, "req_2", ""),
        ],
    );
    let mut index = ScanIndex::default();
    let mut enriched = vec![item];
    apply_claude_effort_evidence_with_index(
        &mut enriched,
        &api.evidence,
        &mut index,
        false,
        &stamp(now),
    );
    assert_eq!(
        enriched[0]
            .session_account_evidence
            .as_ref()
            .unwrap()
            .identity_disposition,
        Some("conflict"),
        "existing billing veto remains"
    );
    let evidence =
        ScanEvidence::new(&api, &trace, BTreeSet::new(), None).with_native_originals(&originals);
    for reported in [false, true] {
        let mut items = enriched.clone();
        let mut groupings = BTreeMap::new();
        if reported {
            let item = &mut items[0];
            let mut sink = identity::RequestSink::for_item(&evidence, item, usize::MAX).unwrap();
            assert!(rebuild_claude_reported_usage(
                item,
                &api.evidence[ROOT],
                &BTreeSet::new(),
                Some(&mut sink)
            ));
            item.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".into());
            groupings.insert(ROOT.to_string(), sink.finish());
        }
        let result = identity::apply_scan(&mut items, &evidence, groupings);
        assert_eq!(result.sent, 1, "reported={reported}: {result:?}");
        assert_eq!(
            items[0]
                .session_account_evidence
                .as_ref()
                .unwrap()
                .identity_disposition,
            Some("conflict")
        );
        let activity = crate::desktop_recent::saved();
        assert_eq!(activity.at(&account, &org1), Some(first));
        assert_eq!(activity.at(&account, &org2), Some(second));
    }
    // Config selection is the existing health observation, independent of
    // which snapshot upload carries the two exact rows.
    let mut health: ottto_protocol::AgentStatusSnapshot = serde_json::from_str(include_str!(
        "../../../../fixtures/agent-status/display-carrier.json"
    ))
    .unwrap();
    health.plan_observations = vec![serde_json::from_value(json!({
        "confidence":"high", "auth_mode":"claude_desktop", "evidence_method":"claude_desktop_session_bucket",
        "account_identifier_hash":account, "is_current":true})).unwrap()];
    let mut response = vec![health.clone()];
    response[0].plan_observations = [&org1, &org2]
        .into_iter()
        .map(|org| {
            serde_json::from_value(json!({
        "confidence":"high", "account_identifier_hash":account,"organization_identifier_hash":org}))
            .unwrap()
        })
        .collect();
    crate::desktop_recent::overlay(&mut response, &health, now);
    assert!(response[0]
        .plan_observations
        .iter()
        .all(|o| o.desktop_recent_at.is_some()));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn desktop_recent_refuses_foreign_conflicting_and_other_account_requests_without_duplicate_index() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("desktop-recent-foreign");
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let at = now - time::Duration::seconds(30);
    let stamp = |at: OffsetDateTime| at.format(&Rfc3339).unwrap();
    let lines = [
        marker(ORG_1),
        json!({"type":"assistant","sessionId":ROOT,
        "entrypoint":"claude-desktop","timestamp":stamp(at),"requestId":"req_foreign",
        "message":{"id":"msg_foreign","model":"claude-haiku-4-5","usage":{"input_tokens":10,"output_tokens":1}}}),
    ];
    let path = dir.join(format!("{ROOT}.jsonl"));
    fs::write(
        &path,
        lines
            .iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let base = parse_claude_code_jsonl_file(&path, &stamp(now), "fp".into())
        .unwrap()
        .remove(0);
    for (case, account) in [
        ("foreign", "f3".repeat(32)),
        ("conflict", "f4".repeat(32)),
        ("account", "f5".repeat(32)),
    ] {
        let mut item = base.clone();
        item.session_account_evidence = Some(SessionAccountEvidence {
            provider: "anthropic",
            account_identifier_hash: Some(account.clone()),
            provider_workspace_hash: Some(org_hash(ORG_1)),
            identity_hash_scheme: "provider-sha256:v1",
            evidence_source: "claude_desktop_original:v1",
            identity_disposition: Some("complete"),
            source_created_at: Some(stamp(at - time::Duration::seconds(1))),
        });
        let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
        if case == "foreign" {
            trace.evidence.insert(
                OTHER_ROOT.into(),
                vec![complete_trace_row(OTHER_ROOT, "req_foreign", "")],
            );
        } else {
            let mut row = complete_api_row(ROOT, "req_foreign", 1, 10, 1, 0);
            row.account_identifier_hash = Some(if case == "account" {
                D64.into()
            } else {
                account.clone()
            });
            api.evidence.insert(ROOT.into(), vec![signed(row)]);
            let owner = complete_trace_row(ROOT, "req_foreign", "");
            trace.evidence.insert(
                ROOT.into(),
                if case == "conflict" {
                    vec![owner.clone(), owner]
                } else {
                    vec![owner]
                },
            );
        }
        let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        let mut items = vec![item];
        let result = identity::apply_scan(&mut items, &evidence, BTreeMap::new());
        assert_eq!(result.sent, 1, "{case}: {result:?}");
        assert_eq!(
            crate::desktop_recent::saved().at(&account, &org_hash(ORG_1)),
            None,
            "{case}"
        );
        if case != "account" {
            assert!(items[0].request_identity_refusals > 0, "{case}");
        }
    }
    fs::remove_dir_all(dir).unwrap();
}

// --- Local account display: current account and account history -------------

/// One own request of the account-display tests: plan, hour bucket, input
/// tokens, identity and own transcript time (`None`: auxiliary request).
struct DisplayRequest {
    plan: Option<&'static str>,
    bucket: &'static str,
    tokens: u64,
    identity: RequestIdentity,
    at: Option<&'static str>,
}

const HOUR_10: &str = "2026-09-01T10:00:00Z";
const HOUR_11: &str = "2026-09-01T11:00:00Z";

fn display_request(
    plan: Option<&'static str>,
    bucket: &'static str,
    tokens: u64,
    identity: RequestIdentity,
    at: Option<&'static str>,
) -> DisplayRequest {
    DisplayRequest {
        plan,
        bucket,
        tokens,
        identity,
        at,
    }
}

fn display_row(plan: Option<&str>) -> SnapshotModelUsage {
    let mut row = typed_row(
        &json!({"model": "claude-haiku-4-5", "input_tokens": 0, "output_tokens": 0,
        "cache_read_tokens": 0, "cache_creation_5m_tokens": 0, "cache_creation_1h_tokens": 0,
        "reasoning_output_tokens": 0, "request_count": 0}),
    );
    row.subscription_product = plan.map(str::to_string);
    row
}

/// An untagged item whose rows the requests reproduce, and the requests.
fn display_item(
    requests: &[DisplayRequest],
) -> (SnapshotItem, Vec<(Contribution, Option<&'static str>)>) {
    let mut item = valid_v6_batch_request().snapshots.remove(0);
    item.provenance.collector = "claude_code_jsonl".to_string();
    let mut top: BTreeMap<Option<&str>, SnapshotModelUsage> = BTreeMap::new();
    let mut buckets: BTreeMap<&str, BTreeMap<Option<&str>, SnapshotModelUsage>> = BTreeMap::new();
    for request in requests {
        for row in [
            top.entry(request.plan)
                .or_insert_with(|| display_row(request.plan)),
            buckets
                .entry(request.bucket)
                .or_default()
                .entry(request.plan)
                .or_insert_with(|| display_row(request.plan)),
        ] {
            row.input_tokens += request.tokens;
            row.request_count += 1;
        }
    }
    item.model_usage = top.into_values().collect();
    item.usage_buckets = buckets
        .into_iter()
        .map(|(bucket_start, rows)| SnapshotUsageBucket {
            bucket_start: bucket_start.to_string(),
            model_usage: rows.into_values().collect(),
            first_activity_at: None,
            last_activity_at: None,
        })
        .collect();
    let contributions = requests
        .iter()
        .map(|request| {
            let mut one = display_row(request.plan);
            one.input_tokens = request.tokens;
            one.request_count = 1;
            (
                Contribution {
                    bucket_start: request.bucket.to_string(),
                    row_key: row_key_from_model_usage(&one),
                    usage: holder_usage(&one, None),
                    identity: request.identity.clone(),
                },
                request.at,
            )
        })
        .collect();
    (item, contributions)
}

fn displayed(requests: &[DisplayRequest]) -> (SnapshotItem, identity::AccountDisplay) {
    let (mut item, contributions) = display_item(requests);
    identity::apply_timed(&mut item, &contributions).expect("reproduces");
    let display = *item.claude_account_display.clone().expect("display");
    (item, display)
}

fn hex(c: char) -> String {
    c.to_string().repeat(64)
}

fn login_org(login: char, org: Option<char>, basis: &'static str) -> RequestIdentity {
    RequestIdentity::Tagged(AuthorityKey {
        login: Some(hex(login)),
        org: org.map(hex),
        basis,
    })
}

/// (account, workspace, plan, requests, input tokens, last use, current).
type Use = (
    Option<String>,
    Option<String>,
    Option<String>,
    u64,
    u64,
    Option<String>,
    bool,
);

fn uses(display: &identity::AccountDisplay) -> Vec<Use> {
    display
        .history
        .iter()
        .map(|entry| {
            (
                entry.account_identifier_hash.clone(),
                entry.organization_identifier_hash.clone(),
                entry.subscription_product.clone(),
                entry.request_count,
                entry.input_tokens,
                entry.last_used_at.clone(),
                entry.current,
            )
        })
        .collect()
}

fn current_of(
    display: &identity::AccountDisplay,
) -> (&str, Option<&str>, Option<&str>, Option<&str>, Option<&str>) {
    let current = &display.current;
    (
        current.status.as_str(),
        current.account_identifier_hash.as_deref(),
        current.organization_identifier_hash.as_deref(),
        current.subscription_product.as_deref(),
        current.unknown_reason.as_deref(),
    )
}

fn owned(value: &str) -> Option<String> {
    Some(value.to_string())
}

/// A -> B -> A inside one hour bucket: the newest request decides, by its own
/// time, in any input order; the history keeps both accounts exactly.
#[test]
fn current_account_follows_the_newest_request_not_its_hour_bucket() {
    let requests = || {
        vec![
            display_request(
                Some("max"),
                HOUR_10,
                10,
                login_org('a', Some('d'), identity::TELEMETRY),
                Some("2026-09-01T10:05:00.100Z"),
            ),
            display_request(
                Some("max"),
                HOUR_10,
                20,
                login_org('b', Some('d'), identity::TELEMETRY),
                Some("2026-09-01T10:20:00Z"),
            ),
            display_request(
                Some("max"),
                HOUR_10,
                30,
                login_org('a', Some('d'), identity::TELEMETRY),
                Some("2026-09-01T10:40:00.250Z"),
            ),
        ]
    };
    let (_, display) = displayed(&requests());
    assert_eq!(
        current_of(&display),
        (
            "known",
            Some(hex('a').as_str()),
            Some(hex('d').as_str()),
            Some("max"),
            None
        )
    );
    assert_eq!(
        display.current.latest_request_at.as_deref(),
        Some("2026-09-01T10:40:00.25Z")
    );
    assert_eq!(
        uses(&display),
        vec![
            (
                owned(&hex('a')),
                owned(&hex('d')),
                owned("max"),
                2,
                40,
                owned("2026-09-01T10:40:00.25Z"),
                true
            ),
            (
                owned(&hex('b')),
                owned(&hex('d')),
                owned("max"),
                1,
                20,
                owned("2026-09-01T10:20:00Z"),
                false
            ),
        ]
    );
    // Every input order folds to the same display.
    for order in [[2, 1, 0], [1, 2, 0], [2, 0, 1]] {
        let mut shuffled = requests();
        let mut reordered = Vec::new();
        for index in order {
            reordered.push(std::mem::replace(
                &mut shuffled[index],
                display_request(None, HOUR_10, 0, RequestIdentity::Missing, None),
            ));
        }
        assert_eq!(displayed(&reordered).1, display, "{order:?}");
    }
    // B last: B is current, across buckets too.
    let mut b_last = requests();
    b_last[1].bucket = HOUR_11;
    b_last[1].at = Some("2026-09-01T11:01:00Z");
    let (_, display) = displayed(&b_last);
    assert_eq!(display.current.account_identifier_hash, owned(&hex('b')));
}

/// A newer unidentified request makes the current account unknown; it never
/// falls back to the previous or the most-used account. Totals stay whole.
#[test]
fn a_newer_unidentified_request_clears_the_current_account() {
    let (item, display) = displayed(&[
        display_request(
            Some("max"),
            HOUR_10,
            500,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T10:05:00Z"),
        ),
        display_request(
            Some("max"),
            HOUR_10,
            7,
            RequestIdentity::Missing,
            Some("2026-09-01T10:06:00Z"),
        ),
        display_request(
            Some("max"),
            HOUR_11,
            9,
            RequestIdentity::Refused(Refusal::Pending),
            Some("2026-09-01T11:00:00Z"),
        ),
    ]);
    assert_eq!(
        current_of(&display),
        (
            "unknown",
            None,
            None,
            None,
            Some("latest_request_unidentified")
        )
    );
    assert_eq!(
        display.current.latest_request_at.as_deref(),
        Some("2026-09-01T11:00:00Z")
    );
    assert_eq!(
        uses(&display),
        vec![
            (
                None,
                None,
                owned("max"),
                2,
                16,
                owned("2026-09-01T11:00:00Z"),
                false
            ),
            (
                owned(&hex('a')),
                owned(&hex('d')),
                owned("max"),
                1,
                500,
                owned("2026-09-01T10:05:00Z"),
                false
            ),
        ]
    );
    let row_requests: u64 = item
        .usage_buckets
        .iter()
        .flat_map(|b| &b.model_usage)
        .map(|r| r.request_count)
        .sum();
    let row_input: u64 = item
        .usage_buckets
        .iter()
        .flat_map(|b| &b.model_usage)
        .map(|r| r.input_tokens)
        .sum();
    assert_eq!(
        display.history.iter().map(|u| u.request_count).sum::<u64>(),
        row_requests
    );
    assert_eq!(
        display.history.iter().map(|u| u.input_tokens).sum::<u64>(),
        row_input
    );
}

/// Requests at the same newest instant that disagree on any of account,
/// workspace or plan leave the current account unknown; agreeing ones do not.
#[test]
fn equal_newest_times_with_different_triples_are_unknown() {
    const AT: Option<&str> = Some("2026-09-01T10:30:00Z");
    for (case, second) in [
        (
            "account",
            display_request(
                Some("max"),
                HOUR_10,
                2,
                login_org('b', Some('d'), identity::TELEMETRY),
                AT,
            ),
        ),
        (
            "workspace",
            display_request(
                Some("max"),
                HOUR_10,
                2,
                login_org('a', Some('e'), identity::TELEMETRY),
                AT,
            ),
        ),
        (
            "plan",
            display_request(
                Some("pro"),
                HOUR_10,
                2,
                login_org('a', Some('d'), identity::TELEMETRY),
                AT,
            ),
        ),
        (
            "unidentified",
            display_request(Some("max"), HOUR_10, 2, RequestIdentity::Missing, AT),
        ),
    ] {
        let (_, display) = displayed(&[
            display_request(
                Some("max"),
                HOUR_10,
                1,
                login_org('a', Some('d'), identity::TELEMETRY),
                AT,
            ),
            second,
            display_request(
                Some("max"),
                HOUR_10,
                4,
                login_org('c', Some('d'), identity::TELEMETRY),
                Some("2026-09-01T10:29:59.999Z"),
            ),
        ]);
        assert_eq!(display.current.status, "unknown", "{case}");
        let reason = if case == "unidentified" {
            "latest_request_unidentified"
        } else {
            "conflicting_latest_requests"
        };
        assert_eq!(
            display.current.unknown_reason.as_deref(),
            Some(reason),
            "{case}"
        );
    }
    // The same triple twice at the newest instant is still that triple.
    let (_, display) = displayed(&[
        display_request(
            Some("max"),
            HOUR_10,
            1,
            login_org('a', Some('d'), identity::TELEMETRY),
            AT,
        ),
        display_request(
            Some("max"),
            HOUR_10,
            2,
            login_org('a', Some('d'), identity::TELEMETRY),
            AT,
        ),
    ]);
    assert_eq!(display.current.account_identifier_hash, owned(&hex('a')));
}

/// A newer request replaces the entire conflicting tie set, even when its
/// storage reuses one of those ties. No old account/workspace/plan may survive.
#[test]
fn newer_request_replaces_conflicting_latest_ties() {
    for (plan, identity) in [
        (Some("max"), login_org('b', Some('e'), identity::TELEMETRY)),
        (Some("pro"), login_org('c', None, identity::TELEMETRY_LOGIN)),
        (None, RequestIdentity::Missing),
    ] {
        let latest = display_request(plan, HOUR_10, 4, identity, Some("2026-09-01T10:31:00Z"));
        let expected = displayed(std::slice::from_ref(&latest)).1.current;
        let (_, actual) = displayed(&[
            display_request(
                Some("max"),
                HOUR_10,
                1,
                login_org('a', Some('d'), identity::TELEMETRY),
                Some("2026-09-01T10:30:00Z"),
            ),
            display_request(
                Some("max"),
                HOUR_10,
                2,
                login_org('b', Some('e'), identity::TELEMETRY),
                Some("2026-09-01T10:30:00Z"),
            ),
            latest,
        ]);
        assert_eq!(actual.current, expected);
        assert_eq!(
            actual
                .history
                .iter()
                .map(|entry| entry.request_count)
                .sum::<u64>(),
            3
        );
    }
}

/// One login across two workspaces and two plans: every exact triple stays
/// its own use, and the current one names the newest request's own workspace
/// and plan, never the first observation's.
#[test]
fn one_login_keeps_each_workspace_and_plan_apart() {
    let (_, display) = displayed(&[
        display_request(
            Some("team"),
            HOUR_10,
            1,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T10:01:00Z"),
        ),
        display_request(
            Some("team"),
            HOUR_10,
            2,
            login_org('a', Some('e'), identity::TELEMETRY),
            Some("2026-09-01T10:02:00Z"),
        ),
        display_request(
            Some("max"),
            HOUR_11,
            4,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T11:03:00Z"),
        ),
        display_request(
            Some("max"),
            HOUR_11,
            8,
            login_org('a', None, identity::TELEMETRY_LOGIN),
            Some("2026-09-01T11:04:00Z"),
        ),
    ]);
    assert_eq!(
        current_of(&display),
        ("known", Some(hex('a').as_str()), None, Some("max"), None)
    );
    assert_eq!(
        uses(&display),
        vec![
            (
                owned(&hex('a')),
                None,
                owned("max"),
                1,
                8,
                owned("2026-09-01T11:04:00Z"),
                true
            ),
            (
                owned(&hex('a')),
                owned(&hex('d')),
                owned("max"),
                1,
                4,
                owned("2026-09-01T11:03:00Z"),
                false
            ),
            (
                owned(&hex('a')),
                owned(&hex('e')),
                owned("team"),
                1,
                2,
                owned("2026-09-01T10:02:00Z"),
                false
            ),
            (
                owned(&hex('a')),
                owned(&hex('d')),
                owned("team"),
                1,
                1,
                owned("2026-09-01T10:01:00Z"),
                false
            ),
        ]
    );
}

/// A transcript request without its own clock proves no order; an auxiliary
/// telemetry-only request, newest or not, never decides the current account
/// or a last use, though its usage counts.
#[test]
fn missing_clocks_and_auxiliary_requests_never_decide_the_current_account() {
    let (_, display) = displayed(&[
        display_request(
            Some("max"),
            HOUR_10,
            1,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T10:01:00Z"),
        ),
        display_request(
            Some("max"),
            HOUR_10,
            2,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some(""),
        ),
    ]);
    assert_eq!(
        current_of(&display),
        (
            "unknown",
            None,
            None,
            None,
            Some("request_order_unavailable")
        )
    );

    let (_, display) = displayed(&[
        display_request(
            Some("max"),
            HOUR_10,
            1,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T10:01:00Z"),
        ),
        // Auxiliary, unidentified and observed later.
        display_request(Some("max"), HOUR_11, 2, RequestIdentity::Missing, None),
        // Auxiliary on another account.
        display_request(
            Some("max"),
            HOUR_11,
            4,
            login_org('b', Some('d'), identity::TELEMETRY),
            None,
        ),
    ]);
    assert_eq!(display.current.account_identifier_hash, owned(&hex('a')));
    assert_eq!(
        uses(&display),
        vec![
            (
                owned(&hex('a')),
                owned(&hex('d')),
                owned("max"),
                1,
                1,
                owned("2026-09-01T10:01:00Z"),
                true
            ),
            (None, None, owned("max"), 1, 2, None, false),
            (
                owned(&hex('b')),
                owned(&hex('d')),
                owned("max"),
                1,
                4,
                None,
                false
            ),
        ]
    );

    // Only auxiliary requests: nothing is provably newest.
    let (_, display) = displayed(&[display_request(
        Some("max"),
        HOUR_10,
        1,
        login_org('a', Some('d'), identity::TELEMETRY),
        None,
    )]);
    assert_eq!(
        display.current.unknown_reason.as_deref(),
        Some("request_order_unavailable")
    );
    assert_eq!(display.current.latest_request_at, None);
}

/// Transcript-marker tags withdraw from the display exactly as from the wire:
/// an org-only newest request is unidentified, and login-only telemetry loses
/// a marker org.
#[test]
fn withdrawn_transcript_tags_withdraw_from_the_display() {
    let (item, display) = displayed(&[
        display_request(
            Some("max"),
            HOUR_10,
            1,
            login_org('a', Some('d'), identity::TELEMETRY_LOGIN),
            Some("2026-09-01T10:01:00Z"),
        ),
        display_request(
            Some("max"),
            HOUR_10,
            2,
            RequestIdentity::Tagged(AuthorityKey {
                login: None,
                org: Some(hex('e')),
                basis: identity::TRANSCRIPT_ORG,
            }),
            Some("2026-09-01T10:02:00Z"),
        ),
    ]);
    assert_eq!(
        display.current.unknown_reason.as_deref(),
        Some("latest_request_unidentified")
    );
    assert_eq!(
        uses(&display),
        vec![
            (
                None,
                None,
                owned("max"),
                1,
                2,
                owned("2026-09-01T10:02:00Z"),
                false
            ),
            (
                owned(&hex('a')),
                None,
                owned("max"),
                1,
                1,
                owned("2026-09-01T10:01:00Z"),
                false
            ),
        ]
    );
    assert!(item
        .request_evidence
        .iter()
        .all(|entry| entry.provider_workspace_hash.is_none()));
}

/// A row whose money cannot be split is untagged on the wire, so its newest
/// request names no account on the card either.
#[test]
fn an_unsplittable_row_untags_its_newest_request() {
    let mut item = one_row_item(&[(10, Some("1")), (20, None)]);
    let requests = vec![
        (
            contribution(&item, 10, Some("1"), login_key(OWNER_A)),
            Some("2026-09-01T10:01:00Z"),
        ),
        (
            contribution(&item, 20, None, login_key(OWNER_A)),
            Some("2026-09-01T10:02:00Z"),
        ),
    ];
    identity::apply_timed(&mut item, &requests).unwrap();
    let display = item.claude_account_display.as_deref().unwrap();
    assert_eq!(
        display.current.unknown_reason.as_deref(),
        Some("latest_request_unidentified")
    );
    assert_eq!(display.history.len(), 1);
    assert_eq!(display.history[0].account_identifier_hash, None);
    assert_eq!(display.history[0].request_count, 2);
}

/// Over the identity caps the item falls back untagged: every use is unnamed
/// and the current account is withheld. An ineligible item gets no display.
/// The display never changes the wire bytes or the fingerprint.
#[test]
fn fallback_withholds_and_ineligible_items_carry_no_display() {
    let requests = (0..17_u8)
        .map(|n| DisplayRequest {
            plan: Some("max"),
            bucket: HOUR_10,
            tokens: 1,
            identity: RequestIdentity::Tagged(AuthorityKey {
                login: Some(format!("{n:064x}")),
                org: None,
                basis: identity::TELEMETRY,
            }),
            at: Some("2026-09-01T10:01:00Z"),
        })
        .collect::<Vec<_>>();
    let (mut item, contributions) = display_item(&requests);
    let result = identity::apply_timed(&mut item, &contributions).unwrap();
    assert!(matches!(result, Tagged::Fallback { .. }), "{result:?}");
    let display = item.claude_account_display.as_deref().unwrap();
    assert_eq!(
        display.current.unknown_reason.as_deref(),
        Some("identity_withheld")
    );
    assert_eq!(
        uses(display),
        vec![(
            None,
            None,
            owned("max"),
            17,
            17,
            owned("2026-09-01T10:01:00Z"),
            false
        )]
    );

    // Rows the requests do not reproduce: today's path, no display.
    let (mut item, mut contributions) = display_item(&requests[..2]);
    contributions.pop();
    let before = serde_json::to_vec(&item).unwrap();
    assert!(identity::apply_timed(&mut item, &contributions).is_err());
    assert!(item.claude_account_display.is_none());
    assert_eq!(serde_json::to_vec(&item).unwrap(), before);

    // Same requests with and without times: identical wire and fingerprint.
    let two = [
        display_request(
            Some("max"),
            HOUR_10,
            1,
            login_org('a', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T10:01:00Z"),
        ),
        display_request(
            Some("pro"),
            HOUR_11,
            2,
            login_org('b', Some('d'), identity::TELEMETRY),
            Some("2026-09-01T11:01:00Z"),
        ),
    ];
    let (mut timed, contributions) = display_item(&two);
    let mut untimed = timed.clone();
    identity::apply_timed(&mut timed, &contributions).unwrap();
    let plain = contributions
        .into_iter()
        .map(|(c, _)| c)
        .collect::<Vec<_>>();
    identity::apply(&mut untimed, &plain).unwrap();
    assert_eq!(
        serde_json::to_vec(&timed).unwrap(),
        serde_json::to_vec(&untimed).unwrap()
    );
    assert_eq!(timed.snapshot_fingerprint, untimed.snapshot_fingerprint);
    let wire = serde_json::to_string(&timed).unwrap();
    assert!(!wire.contains("latest_request_at") && !wire.contains("last_used_at"));
}

/// End to end on parsed requests: the newest own request's account is
/// current, and a response without a complete event clock proves no order.
#[test]
fn transcript_path_current_account_is_the_newest_parsed_request() {
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
    let evidence = ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    identity::reconcile_request_accounts(&mut items, &evidence);
    crate::snapshots::claude_request_money::e2::finish_page(
        &mut items,
        &ScanIndex::default(),
        crate::snapshots::claude_request_money::e2::TelemetryRead::Loaded,
    );
    assert!(items
        .iter()
        .all(crate::snapshots::claude_history_upgrade::is_request_owned_literal));
    let mut unclocked = items.clone();

    identity::apply_scan(&mut items, &evidence, BTreeMap::new());
    let display = items[0].claude_account_display.as_deref().expect("display");
    assert_eq!(display.current.status, "known");
    assert_eq!(
        display.current.account_identifier_hash,
        Some("b".repeat(64))
    );
    assert_eq!(
        display.current.latest_request_at.as_deref(),
        Some("2026-08-02T07:00:03Z")
    );
    let accounts = display
        .history
        .iter()
        .map(|entry| {
            (
                entry.account_identifier_hash.clone(),
                entry.request_count,
                entry.last_used_at.clone(),
                entry.current,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        accounts,
        vec![
            (
                Some("b".repeat(64)),
                2,
                Some("2026-08-02T07:00:03Z".to_string()),
                true
            ),
            (
                Some(OWNER_A.to_string()),
                2,
                Some("2026-08-02T07:00:01Z".to_string()),
                false
            ),
        ]
    );

    unclocked[0]
        .claude_usage_occurrences
        .get_mut("req_1")
        .unwrap()
        .event_clock_complete = false;
    identity::apply_scan(&mut unclocked, &evidence, BTreeMap::new());
    if let Some(display) = unclocked[0].claude_account_display.as_deref() {
        assert_eq!(display.current.status, "unknown");
        assert_eq!(
            display.current.unknown_reason.as_deref(),
            Some("request_order_unavailable")
        );
    }
    let _ = fs::remove_dir_all(dir);
}

include!("claude_request_identity_window_tests.rs");
include!("claude_request_identity_retained_tests.rs");
