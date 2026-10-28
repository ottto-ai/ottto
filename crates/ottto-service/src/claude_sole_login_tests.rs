use super::*;
use crate::test_scratch::ScratchDir;

fn login(n: u8) -> Pair {
    (format!("{n:064x}"), format!("{:064x}", 100))
}
fn owner(scratch: &ScratchDir) -> Owner {
    Owner::recover(scratch.join("identity/history.json"), now())
}
fn observe(owner: &mut Owner, n: u8) -> String {
    let folder = hash("folder", "synthetic");
    assert!(owner.intent(None, None));
    owner.history.observe(
        folder.clone(),
        Some(hash("object", "synthetic")),
        Some(login(n)),
        now(),
    );
    assert!(owner.save());
    folder
}

#[test]
fn lifetime_second_login_or_org_and_switch_back_disable_forever() {
    for change_org in [false, true] {
        let scratch = ScratchDir::new("sole-lifetime");
        let mut o = owner(&scratch);
        let key = observe(&mut o, 1);
        let mut second = login(2);
        if change_org {
            second = (login(1).0, format!("{:064x}", 101));
        }
        o.history.observe(
            key.clone(),
            Some(hash("object", "synthetic")),
            Some(second),
            now(),
        );
        o.history.observe(
            key.clone(),
            Some(hash("object", "synthetic")),
            Some(login(1)),
            now(),
        );
        assert!(o.save());
        let restored = owner(&scratch);
        assert!(restored.history.folders[&key].ineligible);
    }
}

#[test]
fn equal_hash_rewrite_keeps_first_observation_across_restart() {
    let scratch = ScratchDir::new("sole-equal");
    let mut o = owner(&scratch);
    let key = observe(&mut o, 1);
    let first = o.history.folders[&key].first_observed;
    assert_eq!(key, observe(&mut o, 1));
    let restored = owner(&scratch);
    assert_eq!(restored.history.folders[&key].first_observed, first);
    assert!(!restored.history.folders[&key].ineligible);
    assert!(restored.history.folders[&key].gaps.is_empty());
}

#[test]
fn restart_daemon_down_and_unknown_periods_are_gaps() {
    let scratch = ScratchDir::new("sole-restart");
    let mut o = owner(&scratch);
    let key = observe(&mut o, 1);
    let boundary = o.history.boundary;
    let mut restarted = owner(&scratch);
    assert!(restarted.intent(None, None));
    restarted.gap(Gap::DaemonDown);
    restarted.gap(Gap::WatcherError);
    assert!(restarted.save());
    let restored = owner(&scratch);
    assert!(restored.history.folders[&key]
        .gaps
        .iter()
        .any(|(a, b)| *a <= boundary && *b >= boundary));
    assert_eq!(restarted.gaps, [1, 1]);
}

#[test]
fn strict_shape_rejects_absent_optional_fields_and_unknown_fields() {
    let scratch = ScratchDir::new("sole-shape");
    let mut o = owner(&scratch);
    let key = observe(&mut o, 1);
    let mut good = serde_json::to_value(&o.history).unwrap();
    let session = hash("session", "synthetic");
    good["sessions"][&session] =
        serde_json::json!({"first_seen":now(),"folder":key,"attributed":null});
    for (record, field) in [
        ("folders", "pair"),
        ("folders", "object"),
        ("sessions", "folder"),
        ("sessions", "attributed"),
    ] {
        let mut bad = good.clone();
        let record_key = if record == "folders" { &key } else { &session };
        bad[record][record_key]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            serde_json::from_value::<History>(bad).is_err(),
            "{record}.{field}"
        );
    }
    let mut extra = good.clone();
    extra["unexpected"] = true.into();
    assert!(serde_json::from_value::<History>(extra).is_err());
    for field in ["folders", "rollback_pin"] {
        let mut bad = serde_json::json!({"folders":[],"rollback_pin":null});
        bad.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Intent>(bad).is_err());
    }
}

#[test]
fn malformed_store_resets_to_unknown_without_any_eligible_pair() {
    let scratch = ScratchDir::new("sole-invalid");
    let mut o = owner(&scratch);
    let key = observe(&mut o, 1);
    let good = serde_json::to_value(&o.history).unwrap();
    for field in ["version", "enabled", "boundary", "hash", "gap"] {
        let mut bad = good.clone();
        match field {
            "version" => bad["version"] = 9.into(),
            "enabled" => bad["enabled"] = (-1).into(),
            "boundary" => bad["boundary"] = (now() + 86400).into(),
            "hash" => bad["folders"][&key]["pair"][0] = "not-a-hash".into(),
            _ => bad["folders"][&key]["gaps"] = serde_json::json!([[now(), now() - 1]]),
        }
        assert!(durable(&o.path, &serde_json::to_vec(&bad).unwrap()));
        let reset = owner(&scratch);
        assert!(reset.history.folders.is_empty());
        assert!(reset.history.sessions.is_empty());
        assert_eq!(reset.history.enabled, now());
    }
}

#[test]
fn marker_crash_before_or_after_rename_cannot_lose_a_second_login_veto() {
    for after_rename in [false, true] {
        let scratch = ScratchDir::new("sole-crash");
        let mut o = owner(&scratch);
        let key = observe(&mut o, 1);
        assert!(o.intent(None, None));
        o.history.observe(
            key.clone(),
            Some(hash("object", "synthetic")),
            Some(login(2)),
            now(),
        );
        if after_rename {
            assert!(durable(&o.path, &serde_json::to_vec(&o.history).unwrap()));
        }
        // With no commit, the durable intent survives the interrupted save.
        let mut restored = owner(&scratch);
        assert!(restored.history.folders[&key].ineligible);
        assert_eq!(key, observe(&mut restored, 1));
        assert!(owner(&scratch).history.folders[&key].ineligible);
    }
}

#[test]
fn new_folder_in_intent_and_malformed_marker_never_load_as_eligible() {
    let scratch = ScratchDir::new("sole-new-intent");
    let o = owner(&scratch);
    let folder = scratch.join("new-config");
    assert!(o.intent(Some(&folder), None));
    let restored = owner(&scratch);
    assert!(restored.history.folders[&folder_key(&folder)].ineligible);
    assert!(restored.history.folders[&folder_key(&folder)]
        .pair
        .is_none());
    assert!(durable(&o.path.with_extension("intent"), b"not json"));
    let restored = owner(&scratch);
    assert!(restored.history.uncertain);
}

#[test]
fn tentative_pin_rolls_back_on_failed_save_and_on_uncertain_reload() {
    let scratch = ScratchDir::new("sole-pin");
    let mut o = owner(&scratch);
    let session = hash("session", "synthetic");
    o.history.sessions.insert(
        session.clone(),
        Session {
            first_seen: now(),
            folder: None,
            attributed: None,
        },
    );
    // The marker can be saved, but the store rename fails against a directory.
    std::fs::create_dir_all(&o.path).unwrap();
    assert!(!o.pin(&session, login(1)));
    assert!(o.history.sessions[&session].attributed.is_none());
    std::fs::remove_dir(&o.path).unwrap();
    assert!(o.intent(None, Some(&session)));
    o.history.sessions.get_mut(&session).unwrap().attributed = Some(login(1));
    assert!(durable(&o.path, &serde_json::to_vec(&o.history).unwrap()));
    assert!(owner(&scratch).history.sessions[&session]
        .attributed
        .is_none());
    o.history.sessions.get_mut(&session).unwrap().attributed = None;
    assert!(o.pin(&session, login(1)));
    assert!(!o.pin(&session, login(2)));
    assert_eq!(
        owner(&scratch).history.sessions[&session].attributed,
        Some(login(1))
    );
}

#[test]
fn removed_readded_object_or_physical_alias_is_conservatively_disabled() {
    let scratch = ScratchDir::new("sole-alias");
    let mut o = owner(&scratch);
    let key = observe(&mut o, 1);
    o.history.observe(key.clone(), None, None, now());
    o.history.observe(
        key.clone(),
        Some(hash("object", "replacement")),
        Some(login(1)),
        now(),
    );
    assert!(o.history.folders[&key].ineligible);
    let other = hash("folder", "alias");
    o.history.observe(
        other.clone(),
        Some(hash("object", "synthetic")),
        Some(login(1)),
        now(),
    );
    assert!(o.history.folders[&other].ineligible);
}

#[test]
fn bounds_limit_folders_sessions_gaps_and_input_bytes() {
    let scratch = ScratchDir::new("sole-bounds");
    let mut o = owner(&scratch);
    for n in 0..FOLDERS + 1 {
        o.history.observe(format!("{n:064x}"), None, None, now());
    }
    assert_eq!(o.history.folders.len(), FOLDERS);
    let f = o.history.folders.values_mut().next().unwrap();
    for n in 0..GAPS + 20 {
        f.gap(n as i64 * 10, n as i64 * 10 + 1);
    }
    assert_eq!(f.gaps.len(), GAPS);
    assert!(f.gaps.iter().any(|(a, b)| *a == 0 && *b >= 10));
    let bytes = scratch.join("oversized.json");
    let file = std::fs::File::create(&bytes).unwrap();
    file.set_len(BYTES as u64 + 1).unwrap();
    assert!(read::<serde_json::Value>(&bytes).is_none());
    assert!(serde_json::to_vec(&o.history).unwrap().len() <= BYTES);
    let mut huge = History::unknown(now());
    for n in 0..SESSIONS + 1 {
        huge.sessions.insert(
            format!("{n:064x}"),
            Session {
                first_seen: now(),
                folder: None,
                attributed: None,
            },
        );
    }
    assert!(!huge.valid(now()));
}

#[test]
fn serialized_state_has_no_email_name_uuid_or_path() {
    let scratch = ScratchDir::new("sole-privacy");
    let mut o = owner(&scratch);
    let fixture = serde_json::json!({"oauthAccount": {
        "accountUuid":"11111111-1111-4111-8111-111111111111",
        "organizationUuid":"22222222-2222-4222-8222-222222222222",
        "emailAddress":"canary@example.invalid", "displayName":"Canary Name"
    }});
    o.observe(&scratch, Some(&fixture));
    let encoded = serde_json::to_string(&o.history).unwrap();
    for canary in [
        "canary@example.invalid",
        "Canary Name",
        "11111111-1111",
        "22222222-2222",
        scratch.to_str().unwrap(),
    ] {
        assert!(!encoded.contains(canary));
    }
}
