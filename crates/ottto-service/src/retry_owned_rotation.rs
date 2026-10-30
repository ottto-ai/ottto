// Included in snapshot_sync::tests. Native ownership authority fences.
#[test]
fn owned_rotation_native_authority_fences() {
    let device = LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("machine".into()),
        sources: vec!["codex".into()],
    };
    assert!(validate_snapshot_scan_authority(
        &device,
        &device,
        SnapshotSource::Codex,
        true,
        &[1; 32],
        &[1; 32]
    )
    .is_ok());
    for variant in 0..5 {
        let mut current = device.clone();
        let mut endpoint = true;
        let mut account = [1; 32];
        match variant {
            0 => current.device_id = "other".into(),
            1 => current.machine_id = None,
            2 => current.sources.clear(),
            3 => endpoint = false,
            _ => account = [2; 32],
        }
        let error = validate_snapshot_scan_authority(
            &device,
            &current,
            SnapshotSource::Codex,
            endpoint,
            &[1; 32],
            &account,
        )
        .unwrap_err();
        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
    }
    let daemon = test_daemon("machine");
    let initial = daemon.snapshot_scan_account_witness().unwrap();
    let mut account = ottto_protocol::LocalAccountBinding::not_connected();
    account.state = ottto_protocol::LocalAccountState::Connected;
    account.user = Some(ottto_protocol::LocalAccountUser {
        id: "synthetic-u".into(),
        email: "local.invalid".into(),
        display_name: None,
    });
    account.organization = Some(ottto_protocol::LocalAccountOrganization {
        id: "synthetic-o".into(),
        name: "local".into(),
    });
    let daemon = daemon.with_account(account.clone());
    let connected = daemon.snapshot_scan_account_witness().unwrap();
    assert_ne!(initial, connected);
    account.last_refreshed_at = Some("2026-10-05T00:00:00Z".into());
    let daemon = daemon.with_account(account.clone());
    assert_eq!(connected, daemon.snapshot_scan_account_witness().unwrap());
    account.user.as_mut().unwrap().id = "changed".into();
    let daemon = daemon.with_account(account);
    assert_ne!(connected, daemon.snapshot_scan_account_witness().unwrap());
}
