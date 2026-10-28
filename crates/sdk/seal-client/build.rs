//! Compiles a release trust into the SDK, the default of `ClientBuilder::trust`: the JSON file
//! named by `SEAL_RELEASE_TRUST` (absolute, or relative to the workspace root), else this
//! crate's `release-trust.json` (Seal's production trust, published with the crate), else
//! none, and clients must be given a trust. Either is the shape of `deploy/example/trust.json`;
//! it becomes `$OUT_DIR/release-trust.json`.

use std::path::{Path, PathBuf};

const VAR: &str = "SEAL_RELEASE_TRUST";
/// The production trust, next to this file.
const SHIPPED: &str = "release-trust.json";

fn main() {
    println!("cargo:rerun-if-env-changed={VAR}");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("release-trust.json");
    let text = match std::env::var_os(VAR).filter(|v| !v.is_empty()) {
        Some(path) => {
            let path = resolve(Path::new(&path));
            println!("cargo:rerun-if-changed={}", path.display());
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{VAR}={}: {e}", path.display()))
        }
        None => {
            let shipped = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"))
                .join(SHIPPED);
            println!("cargo:rerun-if-changed={}", shipped.display());
            match shipped.is_file() {
                true => std::fs::read_to_string(&shipped).unwrap_or_else(|e| panic!("{}: {e}", shipped.display())),
                false => String::new(),
            }
        }
    };
    std::fs::write(&out, text).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}

/// Relative paths are taken from the workspace root (the nearest ancestor holding `Cargo.lock`).
fn resolve(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_owned();
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let root = manifest.ancestors().find(|dir| dir.join("Cargo.lock").is_file()).unwrap_or(&manifest);
    root.join(path)
}
