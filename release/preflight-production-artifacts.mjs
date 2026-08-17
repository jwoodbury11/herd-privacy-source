#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { canonicalJson, parseArgs, readJson, requireArg } from "./lib/canonical.mjs";
import { preflightProductionArtifacts } from "./lib/production-preflight.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";
import { verifyCanonicalArtifact } from "./lib/signature.mjs";

const MANIFEST_TYPE = "application/vnd.herd.release-manifest.v1+json";

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = requireArg(args, "manifest");
  const manifestText = await readFile(manifestPath, "utf8");
  const manifest = normalizeReleaseManifest(JSON.parse(manifestText), { requireProduction: true });
  if (manifestText !== canonicalJson(manifest)) throw new TypeError("Release manifest is not canonical JSON.");
  const envelope = await readJson(requireArg(args, "signature"));
  verifyCanonicalArtifact({
    bytes: Buffer.from(manifestText),
    envelope,
    publicKey: await readFile(requireArg(args, "public-key"), "utf8"),
    artifactType: MANIFEST_TYPE,
    expectedKey: manifest.trust.releaseManifestSigning,
  });
  const result = await preflightProductionArtifacts({
    manifest,
    evaluatorUrl: requireArg(args, "evaluator-url"),
    rootCertificate: await readFile(requireArg(args, "attestation-root-certificate")),
    configDirectory: requireArg(args, "config-directory"),
    artifactRoot: requireArg(args, "artifact-root"),
    webArchivePath: requireArg(args, "web-archive"),
    iosArchivePath: requireArg(args, "ios-archive"),
    normalizedIosBinaryPath: requireArg(args, "normalized-ios-binary"),
    iosInfo: await readJson(requireArg(args, "ios-info-json")),
    iosEntitlements: await readJson(requireArg(args, "ios-entitlements-json")),
    cosign: args.cosign ?? "cosign",
  });
  process.stdout.write(`${JSON.stringify({ verified: true, ...result })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
