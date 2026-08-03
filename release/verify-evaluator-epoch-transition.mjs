#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import {
  parseArgs,
  readJson,
  requireArg,
  writeCanonicalJson,
} from "./lib/canonical.mjs";
import {
  initialEvaluatorEpochRecord,
  verifyEvaluatorEpochTransition,
} from "./lib/evaluator-epoch.mjs";
import { normalizeProductionReleaseTemplate } from "./lib/production-template.mjs";

async function main() {
  const args = parseArgs(process.argv.slice(2), { boolean: ["initial"] });
  const template = normalizeProductionReleaseTemplate(
    await readJson(requireArg(args, "template")),
  );
  let result;
  if (args.initial) {
    if (args.status) throw new TypeError("--initial and --status are mutually exclusive.");
    result = initialEvaluatorEpochRecord(template, new Date().toISOString());
  } else {
    result = verifyEvaluatorEpochTransition(
      template,
      JSON.parse(await readFile(requireArg(args, "status"), "utf8")),
    );
  }
  await writeCanonicalJson(requireArg(args, "output"), result);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
