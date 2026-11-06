/// [money] Independently finished Codex rows conserve all eight counts and
/// the five cost fields, including absent, present zero and one-sided presence.
/// The expected vectors are fixed independently of the fold implementation.
#[test]
fn codex_independent_fold_matches_fixed_vectors_cost_presence_and_placement() {
    let mut route = route_for(Source::Codex);
    let paths = [
        account_rollout(&route, SESSION, Some("a"), 1),
        account_rollout(&route, ACCOUNT_B, Some("b"), 1),
        account_rollout(&route, GAP, None, 1),
    ];
    let mut base = Vec::new();
    for path in &paths {
        let (_, native) = complete::<Codex>(&route, path, None, |_| {});
        base.extend(native.unwrap().snapshots);
    }
    let machine = "a".repeat(64);
    for item in &base {
        if let Some(evidence) = item.session_account_evidence.as_ref() {
            if let Some(account) = evidence.account_identifier_hash.as_ref() {
                route.index.session_account_bindings.insert(
                    sha256_hex(&["session_owner:v1", &machine, &item.source_session_id]),
                    SessionAccountBinding {
                        account_identifier_hash: account.clone(),
                        workspace_identifier_hash: evidence.provider_workspace_hash.clone(),
                    },
                );
            }
        }
    }
    route
        .index
        .bind_session_accounts(SnapshotSource::Codex, &machine, &mut base, &[]);
    assert!(base[0].model_usage[0].account_identifier_hash.is_some());
    assert!(base[1].model_usage[0].account_identifier_hash.is_some());
    assert_ne!(
        base[0].model_usage[0].account_identifier_hash,
        base[1].model_usage[0].account_identifier_hash
    );
    assert!(base[2].model_usage[0].account_identifier_hash.is_none());
    let vectors = [
        (
            [443683, 2985, 365696, 0, 0, 283, 0, 8],
            [12657642, 49365, 12329984, 0, 0, 19820, 0, 88],
            [13101325, 52350, 12695680, 0, 0, 20103, 0, 96],
        ),
        (
            [873361714, 1153604, 863641472, 0, 0, 416462, 0, 3942],
            [777887464, 1010103, 769131392, 0, 0, 464077, 0, 3526],
            [1651249178, 2163707, 1632772864, 0, 0, 880539, 0, 7468],
        ),
        (
            [11, 12, 13, 14, 15, 16, 17, 8],
            [21, 22, 23, 24, 25, 26, 27, 88],
            [32, 34, 36, 38, 40, 42, 44, 96],
        ),
    ];
    let set = |item: &mut SnapshotItem, v: [u64; 8], cost: Option<&str>| {
        macro_rules! vector {
            ($row:expr) => {{
                $row.input_tokens = v[0];
                $row.output_tokens = v[1];
                $row.cache_read_tokens = v[2];
                $row.cache_creation_5m_tokens = v[3];
                $row.cache_creation_1h_tokens = v[4];
                $row.reasoning_output_tokens = v[5];
                $row.unattributed_total_tokens = v[6];
                $row.request_count = v[7];
            }};
        }
        vector!(item);
        assert_eq!(item.model_usage.len(), 1);
        assert_eq!(item.usage_buckets.len(), 1);
        for row in item.model_usage.iter_mut().chain(
            item.usage_buckets
                .iter_mut()
                .flat_map(|b| &mut b.model_usage),
        ) {
            vector!(row);
            row.cost_usd = cost.map(str::to_owned);
            row.input_cost_usd = cost.map(str::to_owned);
            row.output_cost_usd = cost.map(str::to_owned);
            row.cache_read_cost_usd = cost.map(str::to_owned);
            row.cache_creation_cost_usd = cost.map(str::to_owned);
        }
        item.cost = None;
        item.cache_observations = None;
        item.cache_requests.clear();
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::Codex, item);
    };
    for (shape, (a, b, total)) in vectors.into_iter().enumerate() {
        for (presence, (left, right, sum)) in [
            (None, None, None),
            (Some("0"), Some("0"), Some("0")),
            (Some("1"), None, Some("1")),
            (None, Some("2"), Some("2")),
            (Some("1.25"), Some("2.5"), Some("3.75")),
            (
                Some("100000.000000000001"),
                Some("1"),
                Some("100001.000000000001"),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut original = base[0].clone();
            set(&mut original, a, left);
            let mut revert = base[0].clone();
            set(&mut revert, b, right);
            let mut expected = base[0].clone();
            set(&mut expected, total, sum);
            let singleton = codex_emitted(
                Mode::ColdFull,
                &route.index,
                &[revert.clone(), base[1].clone(), base[2].clone()],
            );
            let mut folded = vec![revert];
            codex_file_join::fold_independent(&mut folded, vec![original]).unwrap();
            let cold = codex_emitted(
                Mode::ColdFull,
                &route.index,
                &[expected.clone(), base[1].clone(), base[2].clone()],
            );
            let actual = codex_emitted(
                Mode::Ram,
                &route.index,
                &[folded[0].clone(), base[1].clone(), base[2].clone()],
            );
            money_oracle::assert_equivalent(&cold, &actual);
            let mut wrong = actual.clone();
            wrong.snapshots.get_mut(SESSION).unwrap()["model_usage"][0]
                ["account_identifier_hash"] = serde_json::json!("f".repeat(64));
            assert!(
                std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &wrong))
                    .is_err(),
                "placement mutation must fail"
            );
            // Actual synthetic head values for the independent review; no raw
            // local/provider identifiers or expected hashes are manufactured.
            println!(
                "CODEX_FOLD_ORACLE {}",
                serde_json::json!({"fixture":format!("codex_sameid_{shape}_{presence}.json"),
                    "requests":total[7],"counts":total,"cost":sum,
                    "base":singleton.normalized,"head":actual.normalized})
            );
        }
    }
}
