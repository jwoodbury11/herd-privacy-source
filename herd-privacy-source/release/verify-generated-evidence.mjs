#!/usr/bin/env node
import path from "node:path";

import { hashFile, parseArgs, readJson, requireArg } from "./lib/canonical.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";

async function matches(descriptor, filePath, label) {
  const digest = await hashFile(filePath);
  if (
    descriptor.name !== path.basename(filePath) ||
    descriptor.sha256 !== digest.sha256 ||
    descriptor.size !== digest.size
  ) {
    throw new TypeError(`${label} does not match the generated file name, size, and SHA-256 digest.`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { boolean: ["require-production"] });
  const manifest = normalizeReleaseManifest(await readJson(requireArg(args, "manifest")), {
    requireProduction: Boolean(args["require-production"]),
  });
  if (manifest.releaseId !== requireArg(args, "release-id")) {
    throw new TypeError("Generated manifest release ID differs from the authorized release ID.");
  }
  if (manifest.source.revision !== requireArg(args, "source-revision")) {
    throw new TypeError("Generated manifest source revision differs from the checked-out revision.");
  }
  if (String(manifest.sourceDateEpoch) !== requireArg(args, "source-date-epoch")) {
    throw new TypeError("Generated manifest source epoch differs from the checked-out revision.");
  }
  await matches(manifest.source.exportArchive, requireArg(args, "source-archive"), "source.exportArchive");
  await matches(manifest.source.exportManifest, requireArg(args, "source-manifest"), "source.exportManifest");
  const sbomPath = requireArg(args, "sbom");
  const sbomName = path.basename(sbomPath);
  const sbom = manifest.evidence.sboms.find(({ name }) => name === sbomName);
  if (!sbom) throw new TypeError(`Release manifest does not reference generated SBOM ${sbomName}.`);
  await matches(sbom, sbomPath, "evidence.sboms");
  process.stdout.write(`${JSON.stringify({ verified: true, releaseId: manifest.releaseId })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
