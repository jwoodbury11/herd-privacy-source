import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifests = await Promise.all(
  [
    "vendor/evaluator-core.sources.json",
    "vendor/relay-core.sources.json",
    "test/vendor/invitee-relay-completion.sources.json",
  ].map(
    async (path) => JSON.parse(await readFile(resolve(root, path), "utf8")),
  ),
);

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

for (const manifest of manifests) {
  assert.equal(
    await digest(resolve(root, manifest.bundle.path)),
    manifest.bundle.sha256,
    `${manifest.bundle.path} changed without a provenance update`,
  );

  for (const source of manifest.sources) {
    assert.equal(
      await digest(resolve(root, source.path)),
      source.sha256,
      `${source.path} changed; regenerate and review the evaluator bundle`,
    );
  }
}

process.stdout.write("vendored evaluator, relay, and invitee contract provenance verified\n");
