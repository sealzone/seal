//! Compiles the release configuration into production builds: the JSON file named by
//! `SEAL_RELEASE_ENCLAVE_CONFIG` (absolute, or relative to the workspace root) becomes
//! `$OUT_DIR/release-config.json`, which the binary includes, so it is part of the image and
//! of the measurement. Unset, the file is empty and a production binary refuses to start.
//! Sim builds read their configuration at run time instead and ignore it.

use std::path::{Path, PathBuf};

const VAR: &str = "SEAL_RELEASE_ENCLAVE_CONFIG";

fn main() {
    println!("cargo:rerun-if-env-changed={VAR}");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("release-config.json");
    let text = match std::env::var_os(VAR).filter(|v| !v.is_empty()) {
        Some(path) => {
            let path = resolve(Path::new(&path));
            println!("cargo:rerun-if-changed={}", path.display());
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{VAR}={}: {e}", path.display()))
        }
        None => String::new(),
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
