//! Frozen 0.1.201 control/load decisions, exercised through the real decoder.
//! This is not a claim that all historical record types are interchangeable.
use super::*;
#[test]
fn historical_decisions_remain_guarded_in_the_integrated_production_decoder() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../fixtures/scan_index/v0.1.201-decisions.json"
    ))
    .unwrap();
    assert_eq!(frozen["commit"], "f174d111fbcdfb0ab9c2abeb299c12d50b435c29");
    for snippet in frozen["snippets"].as_array().unwrap() {
        let source = match snippet["file"].as_str().unwrap() {
            "crates/ottto-service/src/snapshots.rs" => include_str!("../../src/snapshots.rs"),
            "crates/ottto-service/src/snapshots/lenient_decode.rs" => {
                include_str!("../../src/snapshots/lenient_decode.rs")
            }
            "crates/ottto-service/src/snapshots/load_containment.rs" => {
                include_str!("../../src/snapshots/load_containment.rs")
            }
            _ => panic!("unrecognized frozen source"),
        };
        assert_integrated_decision(source, snippet["text"].as_str().unwrap());
    }
}
#[test]
fn actual_decoder_missing_renamed_syntax_and_future_version_behaviour() {
    use ottto_service::snapshots::ScanIndex;
    let s = Scratch::new();
    assert_eq!(ScanIndex::load(&s.root()).unwrap().generation, 0);
    let mut original = ScanIndex::default();
    original.save(&s.root()).unwrap();
    let renamed = s.0.join("renamed-index.json");
    fs::rename(s.root(), &renamed).unwrap();
    assert_eq!(ScanIndex::load(&s.root()).unwrap().generation, 0);
    assert_eq!(ScanIndex::load(&renamed).unwrap().generation, 1);
    // Invalid JSON reaches the original syntax quarantine path, not schema refusal.
    fs::write(
        s.root(),
        b"{\"files\":{},\"schema_version\":2,\"generation\":\"unterminated",
    )
    .unwrap();
    assert_eq!(ScanIndex::load(&s.root()).unwrap().generation, 0);
    assert!(!s.root().exists());
    assert!(fs::read_dir(&s.0).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("corrupt")));
    // Use another scratch tree: recent corruption is intentionally a rebuild-loop refusal.
    let s = Scratch::new();
    for bytes in [b"{\"schema_version\":3,\"generation\":8,\"files\":{}}".as_slice(), b"{\"schema_version\":2,\"generation\":8,\"files\":{},\"accepted_snapshot_fingerprint_ledger_version\":65535}".as_slice()] {
        fs::write(s.root(), bytes).unwrap();
        let error = ScanIndex::load(&s.root()).unwrap_err();
        assert!(format!("{error:#}").contains("scan index refused:"));
        assert_eq!(fs::read(s.root()).unwrap(), bytes);
    }
    let s = Scratch::new();
    s.install();
    let bytes = fs::read(s.root()).unwrap();
    let error = ScanIndex::load(&s.root()).unwrap_err();
    assert!(format!("{error:#}").contains("scan index refused: schema_version"));
    assert_eq!(fs::read(s.root()).unwrap(), bytes);
}

#[test]
fn pinned_0202_also_refuses_schema3_without_inline_maps_before_defaults_can_escape() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../fixtures/scan_index/v0.1.202-decisions.json"
    ))
    .unwrap();
    assert_eq!(frozen["commit"], "79488a7297817edfe1eb5cfc34b779408d511726");
    let source = include_str!("../../src/snapshots/lenient_decode.rs");
    for snippet in frozen["snippets"].as_array().unwrap() {
        assert_integrated_decision(source, snippet["text"].as_str().unwrap());
    }
    let s = Scratch::new();
    s.install();
    let root: Value = serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap();
    for field in [
        "claude_account_family_pending",
        "claude_usage_family_pending",
        "claude_request_census",
    ] {
        assert!(root.get(field).is_none());
    }
    let before = fs::read(s.root()).unwrap();
    let error = ottto_service::snapshots::ScanIndex::load(&s.root()).unwrap_err();
    assert!(format!("{error:#}").contains("scan index refused: schema_version"));
    assert_eq!(fs::read(s.root()).unwrap(), before);
    assert!(!fs::read_dir(&s.0).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("corrupt")));
}

// Frozen historical source stays immutable. Integration changes the structural
// contexts, so pin unchanged controls verbatim and check the new guarded
// dispatch for rewritten contexts; executable legacy behavior is tested above.
fn assert_integrated_decision(source: &str, frozen: &str) {
    if source.contains(frozen) {
        return;
    }
    if frozen.contains("let headers = decoder.index(Pass::Headers)?;") {
        let mode = source
            .split("fn read_persistence_mode<")
            .nth(1)
            .unwrap()
            .split("pub(super) fn read_file")
            .next()
            .unwrap();
        let headers = mode
            .find("let mut headers = decoder.index(Pass::Headers)?;")
            .unwrap();
        let controls = mode.find("controls(&headers, source)?;").unwrap();
        let full = mode
            .find("let result = decoder.index(Pass::Full);")
            .unwrap();
        assert!(headers < controls && controls < full);
        assert!(source.contains("read_persistence_mode(reader, stage, source, false, None)"));
    } else if frozen.contains("if !seen.contains(\"files\")") {
        assert!(source.contains("if !self.persistence_map && !seen.contains(\"files\")"));
        assert!(source.contains("return Err(Error::Refused(\"missing files\"));"));
    } else if frozen.contains("if !path.exists()") {
        assert!(source.contains(
            "scan_index_integration::check_missing(path, scan_index_source_label(source))?;"
        ));
        assert!(source.contains("return Ok((Self::default(), LoadOrigin::Missing));"));
    } else if frozen.contains("let quarantine_path = unique_checkpoint_sibling") {
        assert!(source.contains("fs::rename(path, &quarantine_path).context(\"quarantine invalid local snapshot scan index\")?;"));
        assert!(source.contains("persistence_legacy_recovery: persistence_recovery,"));
        assert!(source.contains("..ScanIndex::default()"));
    } else {
        panic!("unchanged historical control drifted: {frozen}");
    }
}
