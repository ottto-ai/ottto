fn main() {
    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let registry_candidates = [
        manifest_dir.join("../../connectors/registry.generated.json"),
        manifest_dir.join("../../../../connectors/registry.generated.json"),
    ];
    let registry_path = registry_candidates
        .iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("could not find connectors/registry.generated.json"));
    let registry_path = registry_path
        .canonicalize()
        .expect("connector registry path is canonical");
    println!(
        "cargo:rerun-if-changed={}",
        registry_path.to_string_lossy()
    );
    println!(
        "cargo:rustc-env=OTTTO_CONNECTOR_REGISTRY_PATH={}",
        registry_path.to_string_lossy()
    );

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/xpc_shim.c")
            .flag("-fblocks")
            .compile("ottto_xpc_shim");
    }
}
