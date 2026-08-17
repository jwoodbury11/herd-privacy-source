#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { canonicalJson, parseArgs, readJson, requireArg, sha256Hex, writeCanonicalJson } from "./lib/canonical.mjs";
import {
  APPLE_APP_SITE_ASSOCIATION_NAME,
  iosApplicationIdentifier,
  normalizeDeploymentStatement,
  verifyAppleAppSiteAssociation,
} from "./lib/deployment.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";
import { releaseSigningKeyDescriptor, signCanonicalArtifact } from "./lib/signature.mjs";

const ARTIFACT_TYPE = "application/vnd.herd.deployment-statement.v1+json";

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
  const statementPath = requireArg(args, "statement");
  const statementText = await readFile(statementPath, "utf8");
  const statement = normalizeDeploymentStatement(JSON.parse(statementText));
  if (statementText !== canonicalJson(statement)) throw new TypeError("Deployment statement is not canonical JSON.");
  const manifest = normalizeReleaseManifest(await readJson(requireArg(args, "manifest")));
  if (manifest.releaseId !== statement.releaseId) throw new TypeError("Deployment and release IDs differ.");
  const appleAssociation = statement.monitoredResources.find(
    ({ name }) => name === APPLE_APP_SITE_ASSOCIATION_NAME,
  );
  const appleAssociationBytes = await readFile(requireArg(args, "apple-app-site-association"));
  if (
    appleAssociation.sha256 !== sha256Hex(appleAssociationBytes) ||
    appleAssociation.size !== appleAssociationBytes.byteLength
  ) {
    throw new TypeError("Apple app-site association bytes do not match the signed deployment resource descriptor.");
  }
  verifyAppleAppSiteAssociation(
    appleAssociationBytes,
    iosApplicationIdentifier(manifest.artifacts.ios.bundleIdentifier),
  );
  const pinnedKey = manifest.trust.releaseManifestSigning;
  const privateKey = await keyMaterial(args, "private-key", "HERD_RELEASE_SIGNING_PRIVATE_KEY_PEM_B64");
  const publicKey = await keyMaterial(args, "public-key", "HERD_RELEASE_SIGNING_PUBLIC_KEY_PEM_B64");
  const descriptor = releaseSigningKeyDescriptor(publicKey, pinnedKey.keyId);
  if (
    descriptor.publicKey !== pinnedKey.publicKey ||
    descriptor.publicKeySha256 !== pinnedKey.publicKeySha256
  ) {
    throw new TypeError("Deployment signing credential does not match the release manifest.");
  }
  const envelope = signCanonicalArtifact({
    bytes: Buffer.from(statementText),
    privateKey,
    publicKey,
    keyId: pinnedKey.keyId,
    signedAt: statement.deployedAt,
    artifactType: ARTIFACT_TYPE,
  });
  await writeCanonicalJson(requireArg(args, "output"), envelope);
  process.stdout.write(`${JSON.stringify({ verified: true, releaseId: statement.releaseId, keyId: envelope.keyId })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
