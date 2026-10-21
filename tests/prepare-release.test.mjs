import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { prepareRelease } from "../scripts/prepare-release.mjs";

const manifest = '[package]\nname = "ferrovoker"\nversion = "0.0.0"\n';
const lockfile =
  'version = 4\n\n[[package]]\nname = "another-crate"\nversion = "0.0.0"\n\n[[package]]\nname = "ferrovoker"\nversion = "0.0.0"\n';

async function fixture(context, manifestContents = manifest, lockContents = lockfile) {
  const directory = await mkdtemp(join(tmpdir(), "ferrovoker-release-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, "Cargo.toml"), manifestContents);
  await writeFile(join(directory, "Cargo.lock"), lockContents);
  return directory;
}

test("updates both crate versions while preserving dependency versions", async (context) => {
  const directory = await fixture(context);
  await prepareRelease("1.2.3", directory);
  assert.equal(
    await readFile(join(directory, "Cargo.toml"), "utf8"),
    manifest.replace('version = "0.0.0"', 'version = "1.2.3"'),
  );
  assert.equal(
    await readFile(join(directory, "Cargo.lock"), "utf8"),
    lockfile.replace('name = "ferrovoker"\nversion = "0.0.0"', 'name = "ferrovoker"\nversion = "1.2.3"'),
  );
});

test("accepts CI build versions", async (context) => {
  const directory = await fixture(context);
  await prepareRelease("0.0.12345678", directory);
  assert.match(await readFile(join(directory, "Cargo.toml"), "utf8"), /version = "0\.0\.12345678"/);
});

test("preserves CRLF newlines", async (context) => {
  const directory = await fixture(
    context,
    manifest.replaceAll("\n", "\r\n"),
    lockfile.replaceAll("\n", "\r\n"),
  );
  await prepareRelease("1.2.3", directory);
  assert.equal(
    await readFile(join(directory, "Cargo.toml"), "utf8"),
    manifest.replace('version = "0.0.0"', 'version = "1.2.3"').replaceAll("\n", "\r\n"),
  );
});

test("leaves both files untouched if either sentinel is absent", async (context) => {
  for (const [manifestContents, lockContents] of [
    [manifest.replace('version = "0.0.0"', 'version = "1.2.3"'), lockfile],
    [manifest, lockfile.replace('name = "ferrovoker"\nversion = "0.0.0"', 'name = "ferrovoker"\nversion = "1.2.3"')],
  ]) {
    const directory = await fixture(context, manifestContents, lockContents);
    await assert.rejects(prepareRelease("2.0.0", directory), /sentinel/);
    assert.equal(await readFile(join(directory, "Cargo.toml"), "utf8"), manifestContents);
    assert.equal(await readFile(join(directory, "Cargo.lock"), "utf8"), lockContents);
  }
});

test("rejects invalid versions before touching files", async (context) => {
  const directory = await fixture(context);
  for (const version of [undefined, "", "0.0.0", "1.2", "v1.2.3", "01.2.3", "1.2.3; echo unsafe"]) {
    await assert.rejects(prepareRelease(version, directory), /plain SemVer/);
  }
  assert.equal(await readFile(join(directory, "Cargo.toml"), "utf8"), manifest);
  assert.equal(await readFile(join(directory, "Cargo.lock"), "utf8"), lockfile);
});
