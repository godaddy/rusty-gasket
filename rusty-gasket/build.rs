/// Generates build-time metadata (git SHA, build date, rustc version) via the `built` crate.
///
/// `BUILT_TIME_UTC` from the `built` crate captures wall-clock time
/// at the moment `cargo build` runs, which breaks reproducible builds
/// — two builds of the same source produce two different `/health`
/// outputs. The `SOURCE_DATE_EPOCH` environment variable is the
/// de-facto standard for reproducible-build timestamps (Debian, Nix,
/// Bazel, GitHub Actions release tooling all set it), so we re-export
/// it as `GASKET_BUILD_TIME` when present and let the runtime prefer
/// that over the wall-clock fallback.
fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    // Re-watch SOURCE_DATE_EPOCH so cargo re-runs this script if the
    // build env changes between invocations.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        println!("cargo:rustc-env=GASKET_BUILD_TIME_EPOCH={epoch}");
    }
}
