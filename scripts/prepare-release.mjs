import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Replace the crate's checked-in sentinel version in its manifest and lockfile. */
export async function prepareRelease(version, directory = process.cwd()) {
  if (
    !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version ?? "") ||
    version === "0.0.0"
  ) {
    throw new Error("Supply a plain SemVer release or build version other than 0.0.0.");
  }

  const manifestPath = resolve(directory, "Cargo.toml");
  const lockPath = resolve(directory, "Cargo.lock");
  const [manifest, lockfile] = await Promise.all([
    readFile(manifestPath, "utf8"),
    readFile(lockPath, "utf8"),
  ]);
  const packageName = manifest.match(/^name[ \t]*=[ \t]*"([a-zA-Z0-9_-]+)"[ \t]*$/m)?.[1];
  if (!packageName) {
    throw new Error("Cargo.toml must declare a package name.");
  }

  const manifestSentinel = /^(version[ \t]*=[ \t]*")0\.0\.0("[ \t]*\r?)$/m;
  const lockSentinel = new RegExp(
    `(\\[\\[package\\]\\]\\r?\\nname = "${packageName}"\\r?\\nversion = ")0\\.0\\.0(")`,
  );
  // Validate both files before writing either; dependency versions must stay untouched.
  if (!manifestSentinel.test(manifest) || !lockSentinel.test(lockfile)) {
    throw new Error(`Expected the 0.0.0 sentinel for ${packageName} in both Cargo files.`);
  }
  await writeFile(manifestPath, manifest.replace(manifestSentinel, `$1${version}$2`));
  await writeFile(lockPath, lockfile.replace(lockSentinel, `$1${version}$2`));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: node scripts/prepare-release.mjs <version>");
    }
    await prepareRelease(process.argv[2]);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
