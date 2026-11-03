//! AWS Nitro releases. The measurement is `seal_attest::nitro::measurement` of PCR0, PCR1 and
//! PCR2 of the enclave image file (EIF) that `nitro-cli build-enclave` builds from the
//! release's container image with a pinned boot blob set:
//!
//! - The blobs `nitro-cli` boots the image with (`bzImage`, `cmdline`, `init`, `nsm.ko`,
//!   `linuxkit`, from `NITRO_CLI_BLOBS`) are pinned by SHA-256 in a file in `sha256sum` format
//!   committed with the release (`BLOBS`). PCR1 depends only on them, so the `nitro-cli` version
//!   does not matter; other files in the directory (`bzImage.config`) reach only the EIF's
//!   metadata, which is not attested.
//! - The image is named by digest (`<repository>@sha256:<digest>`), the same image whose digest
//!   is the GCP measurement. PCR2 depends on its filesystem, `CMD` and `ENV`.
//! - `build_eif` checks the blobs, builds, and reads the PCRs twice: from the build's output and
//!   from `nitro-cli describe-eif` on the file written. Anyone can rebuild the EIF from the
//!   repository and the pins and compare (`--expect`).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context as _};
use seal_proto::Measurement;
use sha2::{Digest, Sha256};

/// The boot blobs a pin file names, exactly.
pub const BLOBS: [&str; 5] = ["bzImage", "cmdline", "init", "linuxkit", "nsm.ko"];

/// PCR0..2 of an EIF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcrs {
    pub pcr0: [u8; 48],
    pub pcr1: [u8; 48],
    pub pcr2: [u8; 48],
}

impl Pcrs {
    pub fn measurement(&self) -> Measurement {
        seal_attest::nitro::measurement(&self.pcr0, &self.pcr1, &self.pcr2)
    }

    /// From three hex strings.
    pub fn from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> anyhow::Result<Self> {
        let pcr = |name: &str, hex: &str| -> anyhow::Result<[u8; 48]> {
            let bytes = hex_bytes(hex.trim()).ok_or_else(|| anyhow!("{name} is not hex"))?;
            let pcr: [u8; 48] = bytes.try_into().map_err(|_| anyhow!("{name} is not 48 bytes"))?;
            if pcr.iter().all(|b| *b == 0) {
                bail!("{name} is all zero (a debug enclave's)");
            }
            Ok(pcr)
        };
        Ok(Self { pcr0: pcr("PCR0", pcr0)?, pcr1: pcr("PCR1", pcr1)?, pcr2: pcr("PCR2", pcr2)? })
    }

    /// From what `nitro-cli build-enclave` or `describe-eif` prints: a JSON object whose
    /// `Measurements` has `HashAlgorithm` (SHA-384) and `PCR0`, `PCR1`, `PCR2` in hex.
    pub fn from_nitro_cli(output: &str) -> anyhow::Result<Self> {
        let value: serde_json::Value = serde_json::from_str(output).context("nitro-cli's output is not JSON")?;
        let m = value.get("Measurements").ok_or_else(|| anyhow!("nitro-cli's output has no Measurements"))?;
        if let Some(alg) = m.get("HashAlgorithm") {
            if !alg.as_str().is_some_and(|a| a.to_ascii_lowercase().contains("sha384")) {
                bail!("the measurements are not SHA-384: {alg}");
            }
        }
        let get = |name: &str| m.get(name).and_then(|v| v.as_str()).ok_or_else(|| anyhow!("no {name} in Measurements"));
        Self::from_hex(get("PCR0")?, get("PCR1")?, get("PCR2")?)
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect()
}

/// A pin file: `<sha256 hex>  <name>` per line (`sha256sum` output), naming each of `BLOBS`
/// exactly once and nothing else.
pub fn parse_pins(text: &str) -> anyhow::Result<BTreeMap<String, [u8; 32]>> {
    let mut pins = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (hash, name) = line.split_once(char::is_whitespace).ok_or_else(|| anyhow!("pin line {line:?}"))?;
        let name = name.trim().trim_start_matches('*');
        if !BLOBS.contains(&name) {
            bail!("the pins name {name:?}, which is not a boot blob ({})", BLOBS.join(", "));
        }
        let hash: [u8; 32] = hex_bytes(&hash.to_ascii_lowercase())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow!("the pin for {name} is not a SHA-256"))?;
        if pins.insert(name.to_owned(), hash).is_some() {
            bail!("the pins name {name} twice");
        }
    }
    if let Some(missing) = BLOBS.iter().find(|b| !pins.contains_key(**b)) {
        bail!("the pins do not name {missing}");
    }
    Ok(pins)
}

/// Every pinned blob in `dir` has its pinned SHA-256.
pub fn check_blobs(dir: &Path, pins: &BTreeMap<String, [u8; 32]>) -> anyhow::Result<()> {
    for (name, pinned) in pins {
        let path = dir.join(name);
        let bytes = std::fs::read(&path).with_context(|| format!("{}", path.display()))?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if &actual != pinned {
            bail!("{} is not the pinned blob (SHA-256 {})", path.display(), hex(&actual));
        }
    }
    Ok(())
}

/// `<repository>@sha256:<64 hex digits>`.
pub fn check_image(image: &str) -> anyhow::Result<()> {
    let digest = image.rsplit_once("@sha256:").map(|(_, d)| d).unwrap_or_default();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        bail!("{image}: name the release image by digest (<repository>@sha256:<digest>)");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Builds `out` from `image` with the blobs in `blobs`, after checking them against `pins`;
/// the PCRs, read back from the file written.
pub fn build_eif(image: &str, blobs: &Path, pins: &BTreeMap<String, [u8; 32]>, out: &Path) -> anyhow::Result<Pcrs> {
    check_image(image)?;
    check_blobs(blobs, pins)?;
    let built = nitro_cli(
        Command::new("nitro-cli")
            .args(["build-enclave", "--docker-uri", image, "--output-file"])
            .arg(out)
            .env("NITRO_CLI_BLOBS", blobs),
    )?;
    let pcrs = Pcrs::from_nitro_cli(&built)?;
    let described = nitro_cli(Command::new("nitro-cli").args(["describe-eif", "--eif-path"]).arg(out))?;
    if Pcrs::from_nitro_cli(&described)? != pcrs {
        bail!("{}: describe-eif reads other PCRs than the build printed", out.display());
    }
    Ok(pcrs)
}

fn nitro_cli(command: &mut Command) -> anyhow::Result<String> {
    let output = command.output().context("run nitro-cli (aws-nitro-enclaves-cli)")?;
    if !output.status.success() {
        bail!("nitro-cli: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    String::from_utf8(output.stdout).context("nitro-cli's output is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD_OUTPUT: &str = r#"{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "PCR0HEX",
    "PCR1": "PCR1HEX",
    "PCR2": "PCR2HEX"
  }
}"#;

    fn output(pcr0: &str, pcr1: &str, pcr2: &str) -> String {
        BUILD_OUTPUT.replace("PCR0HEX", pcr0).replace("PCR1HEX", pcr1).replace("PCR2HEX", pcr2)
    }

    #[test]
    fn pcrs_from_nitro_cli() {
        let (a, b, c) = ("aa".repeat(48), "bb".repeat(48), "cc".repeat(48));
        let pcrs = Pcrs::from_nitro_cli(&output(&a, &b, &c)).unwrap();
        assert_eq!(pcrs, Pcrs { pcr0: [0xaa; 48], pcr1: [0xbb; 48], pcr2: [0xcc; 48] });
        assert_eq!(pcrs.measurement(), seal_attest::nitro::measurement(&[0xaa; 48], &[0xbb; 48], &[0xcc; 48]));
        // describe-eif prints more around the same Measurements.
        let described = format!(
            r#"{{"EifVersion": 4, "Measurements": {{"PCR0": "{a}", "PCR1": "{b}", "PCR2": "{c}"}}, "IsSigned": false}}"#
        );
        assert_eq!(Pcrs::from_nitro_cli(&described).unwrap(), pcrs);
        for bad in [
            output(&a[2..], &b, &c),
            output(&a, &"zz".repeat(48), &c),
            output(&a, &b, &"00".repeat(48)),
            BUILD_OUTPUT.replace("Sha384", "Sha256"),
            "{}".into(),
            "not json".into(),
        ] {
            assert!(Pcrs::from_nitro_cli(&bad).is_err(), "{bad}");
        }
    }

    fn pin_text(dir: &Path) -> String {
        BLOBS.iter().map(|b| format!("{}  {b}\n", hex(&Sha256::digest(std::fs::read(dir.join(b)).unwrap())))).collect()
    }

    #[test]
    fn blobs_are_checked_against_their_pins() {
        let dir = std::env::temp_dir().join(format!("seal-release-blobs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for blob in BLOBS {
            std::fs::write(dir.join(blob), format!("the {blob} blob")).unwrap();
        }
        std::fs::write(dir.join("bzImage.config"), "metadata only").unwrap();
        let pins = parse_pins(&pin_text(&dir)).unwrap();
        check_blobs(&dir, &pins).unwrap();
        // A changed blob.
        std::fs::write(dir.join("init"), "another init").unwrap();
        assert!(check_blobs(&dir, &pins).unwrap_err().to_string().contains("not the pinned blob"));
        // A missing one.
        std::fs::remove_file(dir.join("init")).unwrap();
        assert!(check_blobs(&dir, &pins).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pin_files() {
        let line = |name: &str| format!("{}  {name}\n", "ab".repeat(32));
        let all: String = BLOBS.iter().map(|b| line(b)).collect();
        assert_eq!(parse_pins(&all).unwrap().len(), 5);
        // `sha256sum -b` marks binary files with `*`.
        assert!(parse_pins(&all.replace("  init", " *init")).is_ok());
        assert!(parse_pins(&all.replace(&line("init"), "")).unwrap_err().to_string().contains("do not name init"));
        assert!(parse_pins(&(all.clone() + &line("init"))).unwrap_err().to_string().contains("twice"));
        assert!(parse_pins(&(all.clone() + &line("bzImage.config"))).is_err());
        assert!(parse_pins(&all.replacen(&"ab".repeat(32), "abc", 1)).is_err());
    }

    #[test]
    fn images_are_named_by_digest() {
        check_image(&format!("registry.example/enclave@sha256:{}", "0f".repeat(32))).unwrap();
        for bad in ["registry.example/enclave:1.2.3", "registry.example/enclave@sha256:abc", "enclave"] {
            assert!(check_image(bad).is_err(), "{bad}");
        }
        assert!(check_image(&format!("e@sha256:{}", "0F".repeat(32))).is_err());
    }
}
