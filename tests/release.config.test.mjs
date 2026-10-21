import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import test from "node:test";
import releaseConfig from "../release.config.js";

// Resolve plugins through the actual release dependency graph to catch writer incompatibility.
const require = createRequire(import.meta.url);
const requireFromSemanticRelease = createRequire(require.resolve("semantic-release"));
const { generateNotes } = await import(
  pathToFileURL(
    requireFromSemanticRelease.resolve("@semantic-release/release-notes-generator"),
  ).href
);
const { analyzeCommits } = await import(
  pathToFileURL(
    requireFromSemanticRelease.resolve("@semantic-release/commit-analyzer"),
  ).href
);

const repositoryUrl = "https://github.com/cmeister2/ferrovoker";
const logger = { log() {}, error() {} };

test("renders complete release notes through semantic-release's actual generator", async () => {
  const plugin = releaseConfig.plugins.find(
    (entry) => Array.isArray(entry) && entry[0] === "@semantic-release/release-notes-generator",
  );
  assert.ok(plugin, "release configuration must include the notes generator");
  const commits = [
    { hash: "a".repeat(40), message: "feat: download Mozilla OneCRL records" },
    { hash: "b".repeat(40), message: "fix: handle empty Chrome CRLSets\n\nCloses #42" },
    {
      hash: "c".repeat(40),
      message:
        "feat: expose CRLSet sequence numbers\n\nBREAKING CHANGE: Download results now include source metadata.",
    },
  ];
  const notes = await generateNotes(plugin[1], {
    cwd: process.cwd(),
    env: {},
    logger,
    options: { repositoryUrl },
    branch: { name: "main" },
    lastRelease: { version: "1.2.3", gitTag: "1.2.3" },
    nextRelease: { version: "2.0.0", gitTag: "2.0.0" },
    commits,
  });

  assert.match(notes, /### Features/);
  assert.match(notes, /### Bug Fixes/);
  assert.match(notes, /### .*BREAKING CHANGES/);
  assert.match(notes, /Download results now include source metadata\./);
  assert.match(notes, /download Mozilla OneCRL records/);
  assert.match(notes, /handle empty Chrome CRLSets/);
  assert.match(notes, /expose CRLSet sequence numbers/);
  assert.ok(notes.includes(`${repositoryUrl}/compare/1.2.3...2.0.0`));
  assert.ok(notes.includes(`${repositoryUrl}/issues/42`));
  for (const commit of commits) {
    assert.ok(notes.includes(`${repositoryUrl}/commit/${commit.hash}`));
  }
});

test("preserves the analyzer's default release rules", async () => {
  assert.ok(releaseConfig.plugins.includes("@semantic-release/commit-analyzer"));
  for (const [message, expected] of [
    ["fix: accept an empty revocation list", "patch"],
    ["perf: reduce CRLSet parsing allocations", "patch"],
    ["feat: download Chrome CRLSets", "minor"],
    ["feat: revise download results\n\nBREAKING CHANGE: Download results include source metadata.", "major"],
    ["docs: clarify revocation coverage", null],
    ["test: cover truncated CRLSets", null],
    ["ci: verify the declared MSRV", null],
    ["chore: refresh release tooling", null],
  ]) {
    const actual = await analyzeCommits({}, {
      cwd: process.cwd(),
      logger,
      commits: [{ hash: "d".repeat(40), message }],
    });
    assert.equal(actual, expected, message);
  }
});
