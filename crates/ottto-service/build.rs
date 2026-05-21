fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/xpc_shim.c")
            .flag("-fblocks")
            .compile("ottto_xpc_shim");
    }
}
