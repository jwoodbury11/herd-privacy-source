#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { parseArgs, readJson, requireArg, sha256Hex, writeCanonicalJson } from "./lib/canonical.mjs";
import { verifyLocalArtifacts } from "./lib/artifacts.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";

async function main() {
  const args = parseArgs(process.argv.slice(2), { boolean: ["require-production"] });
  const inputPath = requireArg(args, "input");
  const outputPath = requireArg(args, "output");
  const normalized = normalizeReleaseManifest(await readJson(inputPath), {
    requireProduction: Boolean(args["require-production"]),
  });
  if (args["artifact-root"]) await verifyLocalArtifacts(normalized, args["artifact-root"]);
  await writeCanonicalJson(outputPath, normalized);
  const bytes = await readFile(outputPath);
  process.stdout.write(`${JSON.stringify({ output: outputPath, sha256: sha256Hex(bytes), size: bytes.byteLength })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
