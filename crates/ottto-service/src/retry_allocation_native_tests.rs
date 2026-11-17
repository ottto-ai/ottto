#[test]
fn bounded_retry_envelope_auxiliary_shape_refuses_before_native_decode() {
    let shallow = format!("{{\"future\":[{}0]}}", "0,".repeat(24_000));
    assert!(shallow.len() < crate::snapshot_retry::RESPONSE_BYTES);
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        assert!(
            crate::snapshot_retry::decode_state::<serde_json::Value>(shallow.as_bytes()).is_err()
        );
        let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(crate::snapshot_retry::decode_state::<serde_json::Value>(deep.as_bytes()).is_err());
        assert!(crate::snapshot_retry::decode_state::<serde_json::Value>(b"{} {}").is_err());
    });
    assert!(allocation.requested_peak < 64 * 1024);
    // The response body has a separate cap: legal ACK arrays are not auxiliary
    // checkpoint state and must keep their existing native response contract.
    assert!(serde_json::from_str::<serde_json::Value>(&shallow).is_ok());
}
