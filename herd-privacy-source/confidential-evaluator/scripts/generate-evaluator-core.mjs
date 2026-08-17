import { execFile } from "node:child_process";
import { resolve, dirname } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repository = resolve(root, "..");

await execute(resolve(repository, "evaluator-service/node_modules/.bin/esbuild"), [
  resolve(repository, "evaluator-service/lib/evaluate.ts"),
  "--bundle",
  "--platform=node",
  "--format=esm",
  "--target=node20",
  "--legal-comments=none",
  "--banner:js=// Generated from evaluator-service/lib/evaluate.ts; do not edit by hand.",
  `--outfile=${resolve(root, "vendor/evaluator-core.mjs")}`,
]);
