#!/usr/bin/env node
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

import { verifyLocalArtifacts } from "./lib/artifacts.mjs";
import { canonicalJson, parseArgs, readJson, requireArg } from "./lib/canonical.mjs";
import { verifyProvenanceBundles } from "./lib/provenance-verification.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";
import { verifyCanonicalArtifact } from "./lib/signature.mjs";

const run = promisify(execFile);
const ARTIFACT_TYPE = "application/vnd.herd.release-manifest.v1+json";

async function verifySigstore(args, manifestPath) {
  if (!args["sigstore-bundle"]) return;
  const identity = requireArg(args, "certificate-identity");
  const issuer = requireArg(args, "certificate-oidc-issuer");
  await run(
    args.cosign ?? "cosign",
    [
      "verify-blob",
      "--bundle",
      args["sigstore-bundle"],
      "--certificate-identity",
      identity,
      "--certificate-oidc-issuer",
      issuer,
      manifestPath,
    ],
    { maxBuffer: 1024 * 1024 },
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { boolean: ["require-production"] });
  const manifestPath = requireArg(args, "manifest");
  const signaturePath = requireArg(args, "signature");
  const publicKeyPath = requireArg(args, "public-key");
  const manifestText = await readFile(manifestPath, "utf8");
  const manifest = normalizeReleaseManifest(JSON.parse(manifestText), {
    requireProduction: Boolean(args["require-production"]),
  });
  if (manifestText !== canonicalJson(manifest)) throw new TypeError("Release manifest is not canonical JSON.");
  const envelopeText = await readFile(signaturePath, "utf8");
  const envelope = await readJson(signaturePath);
  if (envelopeText !== canonicalJson(envelope)) throw new TypeError("Release signature envelope is not canonical JSON.");
  verifyCanonicalArtifact({
    bytes: Buffer.from(manifestText),
    envelope,
    publicKey: await readFile(publicKeyPath, "utf8"),
    artifactType: ARTIFACT_TYPE,
    expectedKey: manifest.trust.releaseManifestSigning,
  });
  const requireProduction = Boolean(args["require-production"]);
  if (requireProduction && !args["artifact-root"]) {
    throw new TypeError("--artifact-root is required for production provenance verification.");
  }
  const artifactCount = args["artifact-root"]
    ? await verifyLocalArtifacts(manifest, args["artifact-root"])
    : 0;
  const provenanceBundles = requireProduction
    ? await verifyProvenanceBundles(manifest, args["artifact-root"], {
        cosign: args.cosign ?? "cosign",
      })
    : 0;
  await verifySigstore(args, manifestPath);
  process.stdout.write(
    `${JSON.stringify({ verified: true, releaseId: manifest.releaseId, artifactCount, provenanceBundles, sigstore: Boolean(args["sigstore-bundle"]) })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
