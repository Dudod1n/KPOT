fn main() {
    for path in [
        "build.rs",
        "scripts/build_icons.py",
        "assets/krot.svg",
        "assets/krot.png",
        "assets/krot-tray.png",
        "assets/krot.ico",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/krot.ico")
            .set("ProductName", "КРОТ")
            .set("FileDescription", "КРОТ — менеджер SSH-туннелей")
            .compile()
            .expect("Windows application resources must compile");
    }
}
