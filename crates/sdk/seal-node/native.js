"use strict";
// Finds the native addon for this platform: `seal.<platform>.node` next to this file (what
// `build.sh` writes), else the prebuilt package `@sealzone/sdk-<platform>`, as napi-rs lays
// them out. `build.sh` asks `platform()` for the name.

const { join } = require("node:path");
const { existsSync } = require("node:fs");

/** `linux-x64-gnu`, `linux-arm64-musl`, `darwin-arm64`, ... */
function platform() {
  const { platform: os, arch } = process;
  if (os === "linux") {
    return `${os}-${arch}-${isMusl() ? "musl" : "gnu"}`;
  }
  return `${os}-${arch}`;
}

function isMusl() {
  try {
    // glibc reports its version; musl does not.
    return !process.report.getReport().header.glibcVersionRuntime;
  } catch {
    return false;
  }
}

function load() {
  const name = platform();
  const local = join(__dirname, `seal.${name}.node`);
  if (existsSync(local)) {
    return require(local);
  }
  try {
    return require(`@sealzone/sdk-${name}`);
  } catch (e) {
    throw new Error(
      `@sealzone/sdk has no native addon for ${name}: install @sealzone/sdk-${name}, or build one with build.sh (${e.message})`,
    );
  }
}

module.exports = { platform, load };
