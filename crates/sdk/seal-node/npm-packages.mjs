// Lays out the per-platform npm packages of @sealzone/sdk from built addons, as napi-rs does:
// one `@sealzone/sdk-<platform>` package per `seal.<platform>.node`, and this package listing
// them as optional dependencies at the same version.
//
//   node npm-packages.mjs ADDONS_DIR OUT_DIR VERSION
//
// ADDONS_DIR holds `seal.<platform>.node` files (each from `build.sh --release` on its
// platform); OUT_DIR gets `<platform>/package.json` + its addon, and `sdk/` (this package).
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [addons, out, version] = process.argv.slice(2);
if (!addons || !out || !/^\d+\.\d+\.\d+/.test(version ?? "")) {
  console.error("usage: node npm-packages.mjs ADDONS_DIR OUT_DIR VERSION");
  process.exit(2);
}
const here = dirname(fileURLToPath(import.meta.url));
const main = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));

/** `linux-x64-gnu` → npm's os, cpu and libc fields. */
function fields(platform) {
  const [os, cpu, abi] = platform.split("-");
  return { os: [os], cpu: [cpu], ...(abi ? { libc: [abi === "musl" ? "musl" : "glibc"] } : {}) };
}

const platforms = [];
for (const file of readdirSync(addons).filter((f) => /^seal\..+\.node$/.test(f)).sort()) {
  const platform = file.slice("seal.".length, -".node".length);
  const dir = join(out, platform);
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(addons, file), join(dir, file));
  const pkg = {
    name: `@sealzone/sdk-${platform}`,
    version,
    description: `The native addon of @sealzone/sdk for ${platform}.`,
    license: main.license,
    homepage: main.homepage,
    // npm's trusted publishing and provenance match it against the publishing repository.
    repository: main.repository,
    main: file,
    files: [file],
    ...fields(platform),
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  platforms.push(platform);
}

const expected = Object.keys(main.optionalDependencies).map((n) => n.slice("@sealzone/sdk-".length)).sort();
if (JSON.stringify(platforms) !== JSON.stringify(expected)) {
  console.error(`built ${platforms.join(", ")}; package.json lists ${expected.join(", ")}`);
  process.exit(1);
}

const sdk = join(out, "sdk");
mkdirSync(sdk, { recursive: true });
for (const file of [...main.files, "README.md"]) {
  copyFileSync(join(here, file), join(sdk, file));
}
const optionalDependencies = Object.fromEntries(platforms.map((p) => [`@sealzone/sdk-${p}`, version]));
writeFileSync(join(sdk, "package.json"), JSON.stringify({ ...main, version, optionalDependencies }, null, 2) + "\n");
console.log(`${platforms.length} platform packages and @sealzone/sdk ${version} in ${out}`);
