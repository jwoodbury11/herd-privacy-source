import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { SCHEDULER_RUNTIME_VARIABLE_NAMES } from "../src/worker.mjs";

const serviceRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(serviceRoot, "..");

async function isReadable(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

test("no drift-prone manual scheduler runner can receive the production bearer", async () => {
  assert.equal(
    await isReadable(resolve(serviceRoot, ".github/workflows/sweep.yml")),
    false,
  );
  assert.equal(
    await isReadable(resolve(serviceRoot, ".github/scripts/sweep.mjs")),
    false,
  );

  const readme = await readFile(resolve(serviceRoot, "README.md"), "utf8");
  assert.match(readme, /no repository-hosted manual or\s+GitHub Actions recovery runner/iu);
  assert.match(readme, /bearer is attached only to the pinned Herd origin and never\s+to the evaluator/iu);
  assert.doesNotMatch(readme, /manual-only recovery tool/iu);
});

test("the courier validates every manifest-derived scheduler runtime variable", async () => {
  const productionConfig = await readFile(
    resolve(repositoryRoot, "release/lib/production-config.mjs"),
    "utf8",
  );
  const schedulerBlock = productionConfig.match(
    /const schedulerRuntimeVariables = \{([\s\S]*?)\n  \};/u,
  );
  assert.ok(schedulerBlock, "production config must define scheduler variables");
  const generatedNames = [
    ...schedulerBlock[1].matchAll(/^\s{4}(HERD_[A-Z0-9_]+):/gmu),
  ].map((match) => match[1]).sort();

  assert.deepEqual(
    [...SCHEDULER_RUNTIME_VARIABLE_NAMES].sort(),
    generatedNames,
  );
});
