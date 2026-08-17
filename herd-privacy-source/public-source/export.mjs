#!/usr/bin/env node
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseArgs,
  readJson,
  requireArg,
  writeCanonicalJson,
} from "../release/lib/canonical.mjs";
import {
  assertCleanRepository,
  collectExportFiles,
  createExportManifest,
  createTarArchive,
  normalizeExportPolicy,
} from "./lib/export-core.mjs";

async function main() {
  const args = parseArgs(process.argv.slice(2), { boolean: ["require-clean"] });
  const scriptRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const root = path.resolve(args.root ?? scriptRoot);
  const policyPath = path.resolve(args.policy ?? path.join(root, "public-source/export-policy.json"));
  const outputPath = path.resolve(requireArg(args, "output"));
  const manifestPath = path.resolve(requireArg(args, "manifest"));
  const sourceRevision = requireArg(args, "source-revision");
  const sourceDateEpoch = Number(requireArg(args, "source-date-epoch"));
  if (args["require-clean"]) await assertCleanRepository(root);
  const policyBytes = await readFile(policyPath);
  const policy = normalizeExportPolicy(await readJson(policyPath));
  const files = await collectExportFiles(root, policy);
  const policyRelativePath = path.relative(root, policyPath).replaceAll(path.sep, "/");
  const manifest = createExportManifest({
    files,
    policyBytes,
    policyPath: policyRelativePath,
    sourceRevision,
    sourceDateEpoch,
    archivePrefix: policy.archivePrefix,
  });
  const archive = createTarArchive(files, manifest, sourceDateEpoch);
  await mkdir(path.dirname(outputPath), { recursive: true });
  const temporaryPath = `${outputPath}.tmp-${process.pid}`;
  await writeFile(temporaryPath, archive, { mode: 0o600 });
  await rename(temporaryPath, outputPath);
  await writeCanonicalJson(manifestPath, manifest);
  process.stdout.write(
    `${JSON.stringify({ output: outputPath, manifest: manifestPath, files: files.length, bytes: archive.byteLength })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
