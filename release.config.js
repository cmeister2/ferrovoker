/** Publish the Rust crate and its corresponding GitHub release. */
export default {
  branches: ["main", "master"],
  repositoryUrl: "https://github.com/cmeister2/ferrovoker",
  tagFormat: "${version}",
  plugins: [
    "@semantic-release/commit-analyzer",
    [
      "@semantic-release/release-notes-generator",
      { preset: "conventionalcommits" },
    ],
    [
      "@semantic-release/exec",
      {
        prepareCmd: "node scripts/prepare-release.mjs ${nextRelease.version}",
        publishCmd: "cargo publish --locked --allow-dirty",
      },
    ],
    "@semantic-release/github",
  ],
};
