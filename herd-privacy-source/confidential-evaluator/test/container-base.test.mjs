import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const checker = fileURLToPath(
  new URL("../scripts/require-image-digest.mjs", import.meta.url),
);
const digest = "a".repeat(64);

function check(reference) {
  return spawnSync(process.execPath, [checker, reference], {
    encoding: "utf8",
  });
}

test("accepts only immutable supported official Node Bookworm-slim bases", () => {
  for (const reference of [
    `node:22.13.0-bookworm-slim@sha256:${digest}`,
    `node:22.99.7-bookworm-slim@sha256:${digest}`,
  ]) {
    const result = check(reference);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /immutable supported Node base image/u);
  }
});

test("rejects floating, unsupported, or non-official base references", () => {
  for (const reference of [
    "",
    "node:22-bookworm-slim",
    `node:20.18.0-bookworm-slim@sha256:${digest}`,
    `node:22.12.0-bookworm-slim@sha256:${digest}`,
    `node:22.13.0-alpine@sha256:${digest}`,
    `registry.example/node:22.13.0-bookworm-slim@sha256:${digest}`,
    `node:22.13.0-bookworm-slim@sha256:${"A".repeat(64)}`,
  ]) {
    const result = check(reference);
    assert.notEqual(result.status, 0, reference);
    assert.match(result.stderr, /immutable official node:22\.13\.0-or-newer/u);
  }
});
