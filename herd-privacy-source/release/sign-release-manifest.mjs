#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import {
  canonicalJson,
  parseArgs,
  readJson,
  requireArg,
  writeCanonicalJson,
} from "./lib/canonical.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";
import { signCanonicalArtifact } from "./lib/signature.mjs";

const ARTIFACT_TYPE = "application/vnd.herd.release-manifest.v1+json";

async function keyMaterial(args, argumentName, environmentName) {
  if (args[argumentName] && process.env[environmentName]) {
    throw new TypeError(`Use either --${argumentName} or ${environmentName}, not both.`);
  }
  if (args[argumentName]) return readFile(args[argumentName], "utf8");
  const encoded = process.env[environmentName];
  if (!encoded) throw new TypeError(`Missing --${argumentName} or ${environmentName}.`);
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded.replace(/\s+/gu, "")) {
    throw new TypeError(`${environmentName} must be canonical base64-encoded PEM.`);
  }
  return bytes.toString("utf8");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = requireArg(args, "manifest");
  const outputPath = requireArg(args, "output");
  const manifestText = await readFile(manifestPath, "utf8");
  const manifest = normalizeReleaseManifest(JSON.parse(manifestText));
  if (manifestText !== canonicalJson(manifest)) {
    throw new TypeError("Release manifest must be canonical before signing.");
  }
  const expectedKey = manifest.trust.releaseManifestSigning;
  const privateKey = await keyMaterial(
    args,
    "private-key",
    "HERD_RELEASE_SIGNING_PRIVATE_KEY_PEM_B64",
  );
  const publicKey = await keyMaterial(
    args,
    "public-key",
    "HERD_RELEASE_SIGNING_PUBLIC_KEY_PEM_B64",
  );
  const envelope = signCanonicalArtifact({
    bytes: Buffer.from(manifestText),
    privateKey,
    publicKey,
    keyId: expectedKey.keyId,
    signedAt: manifest.createdAt,
    artifactType: ARTIFACT_TYPE,
  });
  if (envelope.publicKeySha256 !== expectedKey.publicKeySha256) {
    throw new TypeError("Release signing credential does not match the manifest trust pin.");
  }
  const { releaseSigningKeyDescriptor } = await import("./lib/signature.mjs");
  const descriptor = releaseSigningKeyDescriptor(publicKey, expectedKey.keyId);
  if (descriptor.publicKey !== expectedKey.publicKey) {
    throw new TypeError("Release signing public key bytes do not match the manifest trust pin.");
  }
  await writeCanonicalJson(outputPath, envelope);
  process.stdout.write(`${JSON.stringify({ output: outputPath, keyId: envelope.keyId, digest: envelope.signedDigest.value })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
