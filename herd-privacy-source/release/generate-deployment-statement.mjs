#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { parseArgs, readJson, requireArg, sha256Hex, writeCanonicalJson } from "./lib/canonical.mjs";
import { normalizeDeploymentStatement } from "./lib/deployment.mjs";

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const output = requireArg(args, "output");
  const statement = normalizeDeploymentStatement(await readJson(requireArg(args, "input")));
  await writeCanonicalJson(output, statement);
  const bytes = await readFile(output);
  process.stdout.write(`${JSON.stringify({ output, releaseId: statement.releaseId, sha256: sha256Hex(bytes), size: bytes.byteLength })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
