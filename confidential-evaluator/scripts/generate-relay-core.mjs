import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repository = resolve(root, "..");
const upstreamPath = resolve(repository, "evaluator-service/lib/relay.ts");
const esbuildPath = resolve(
  repository,
  "evaluator-service/node_modules/.bin/esbuild",
);

function replaceOnce(source, before, after) {
  const first = source.indexOf(before);
  assert.notEqual(first, -1, `relay transform anchor missing: ${before}`);
  assert.equal(
    source.indexOf(before, first + before.length),
    -1,
    `relay transform anchor is ambiguous: ${before}`,
  );
  return `${source.slice(0, first)}${after}${source.slice(first + before.length)}`;
}

let transformed = await readFile(upstreamPath, "utf8");
transformed = replaceOnce(
  transformed,
  '} from "./evaluate";',
  '} from "../../evaluator-service/lib/evaluate.ts";',
);
transformed = replaceOnce(
  transformed,
  "  type EvaluationResult,\n  type EvaluatorBindings,",
  "  type EvaluationResult,\n  type EvaluatorBindings,\n  type EvaluatorConfig,",
);
transformed = replaceOnce(
  transformed,
  "  bindings: EvaluatorBindings,\n  now = new Date(),\n  evaluationAuthorizer?: EvaluationAuthorizer,\n): Promise<Response> {",
  "  bindings: EvaluatorBindings,\n  now = new Date(),\n  evaluationAuthorizer?: EvaluationAuthorizer,\n  configOverride?: EvaluatorConfig,\n  signingConfigOverride?: SigningConfig,\n): Promise<Response> {",
);
transformed = replaceOnce(
  transformed,
  "    const config = await loadConfig(bindings);",
  "    const config = configOverride ?? (await loadConfig(bindings));",
);
transformed = replaceOnce(
  transformed,
  "    const signingConfig = await loadSigningConfig(bindings);",
  "    const signingConfig =\n      signingConfigOverride ?? (await loadSigningConfig(bindings));",
);

const temporaryDirectory = resolve(root, ".relay-core-build");
await mkdir(temporaryDirectory, { recursive: false, mode: 0o700 });
try {
  const entry = resolve(temporaryDirectory, "relay.ts");
  await writeFile(entry, transformed, { encoding: "utf8", mode: 0o600 });
  await execute(esbuildPath, [
    entry,
    "--bundle",
    "--platform=node",
    "--format=esm",
    "--target=node20",
    "--legal-comments=none",
    "--banner:js=// Generated from evaluator-service/lib/relay.ts with reviewed dependency injection; do not edit by hand.",
    `--outfile=${resolve(root, "vendor/relay-core.mjs")}`,
  ]);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}
