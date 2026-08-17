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
import { verifyCanonicalArtifact } from "./lib/signature.mjs";

const MANIFEST_TYPE = "application/vnd.herd.release-manifest.v1+json";
const DEPLOYMENT_TYPE = "application/vnd.herd.deployment-statement.v1+json";

function httpsUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${label} must be an HTTPS URL.`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new TypeError(`${label} must be a safe HTTPS URL.`);
  }
  return url.toString();
}

function fileReference(bytes, url) {
  return { url: httpsUrl(url, "published artifact URL"), sha256: sha256Hex(bytes), size: bytes.byteLength };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = requireArg(args, "manifest");
  const manifestSignaturePath = requireArg(args, "manifest-signature");
  const deploymentPath = requireArg(args, "deployment");
  const deploymentSignaturePath = requireArg(args, "deployment-signature");
  const publicKey = await readFile(requireArg(args, "public-key"), "utf8");

  const manifestBytes = await readFile(manifestPath);
  const manifest = normalizeReleaseManifest(JSON.parse(manifestBytes.toString("utf8")));
  if (manifestBytes.toString("utf8") !== canonicalJson(manifest)) throw new TypeError("Release manifest is not canonical.");
  const manifestSignatureBytes = await readFile(manifestSignaturePath);
  const manifestSignature = JSON.parse(manifestSignatureBytes.toString("utf8"));
  verifyCanonicalArtifact({
    bytes: manifestBytes,
    envelope: manifestSignature,
    publicKey,
    artifactType: MANIFEST_TYPE,
    expectedKey: manifest.trust.releaseManifestSigning,
  });

  const deploymentBytes = await readFile(deploymentPath);
  const deployment = normalizeDeploymentStatement(JSON.parse(deploymentBytes.toString("utf8")));
  if (deploymentBytes.toString("utf8") !== canonicalJson(deployment)) {
    throw new TypeError("Deployment statement is not canonical.");
  }
  if (deployment.releaseId !== manifest.releaseId) throw new TypeError("Deployment and manifest release IDs differ.");
  const deploymentSignatureBytes = await readFile(deploymentSignaturePath);
  const deploymentSignature = JSON.parse(deploymentSignatureBytes.toString("utf8"));
  verifyCanonicalArtifact({
    bytes: deploymentBytes,
    envelope: deploymentSignature,
    publicKey,
    artifactType: DEPLOYMENT_TYPE,
    expectedKey: manifest.trust.releaseManifestSigning,
  });
  if (
    deployment.manifest.sha256 !== sha256Hex(manifestBytes) ||
    deployment.manifest.size !== manifestBytes.byteLength ||
    deployment.manifestSignature.sha256 !== sha256Hex(manifestSignatureBytes) ||
    deployment.manifestSignature.size !== manifestSignatureBytes.byteLength
  ) {
    throw new TypeError("Deployment statement does not bind the supplied release manifest and signature.");
  }
  if (
    deployment.endpoints.webOrigin !== manifest.artifacts.web.publicOrigin ||
    deployment.monitoredResources.find(({ name }) => name === "entry-document")?.sha256 !==
      manifest.artifacts.web.entryDocumentSha256 ||
    deployment.monitoredResources.find(({ name }) => name === "asset-manifest")?.sha256 !==
      manifest.artifacts.web.assetManifestSha256
  ) {
    throw new TypeError("Deployment web resources do not match the release manifest.");
  }
  const appleAssociation = deployment.monitoredResources.find(
    ({ name }) => name === APPLE_APP_SITE_ASSOCIATION_NAME,
  );
  const appleAssociationBytes = await readFile(requireArg(args, "apple-app-site-association"));
  if (
    appleAssociation.sha256 !== sha256Hex(appleAssociationBytes) ||
    appleAssociation.size !== appleAssociationBytes.byteLength
  ) {
    throw new TypeError("Apple app-site association bytes do not match the deployment resource descriptor.");
  }
  verifyAppleAppSiteAssociation(
    appleAssociationBytes,
    iosApplicationIdentifier(manifest.artifacts.ios.bundleIdentifier),
  );
  const expectedDeployments = new Map([
    ["web", manifest.artifacts.web.deploymentArchive.sha256],
    ["ordinary-api", manifest.artifacts.ordinaryApi.sha256],
    ["evaluator", manifest.artifacts.evaluator.sha256],
    ["scheduler", manifest.artifacts.scheduler.sha256],
  ]);
  if (
    deployment.platformDeployments.some(
      ({ component, artifactSha256 }) => expectedDeployments.get(component) !== artifactSha256,
    )
  ) {
    throw new TypeError("Platform deployment IDs are not bound to the released artifact hashes.");
  }

  const output = {
    schemaVersion: 1,
    releaseId: manifest.releaseId,
    previousRelease: manifest.previousRelease,
    protocol: manifest.protocol,
    releaseSigningKey: manifest.trust.releaseManifestSigning,
    manifest: {
      ...fileReference(manifestBytes, deployment.manifest.url),
      signature: fileReference(manifestSignatureBytes, deployment.manifestSignature.url),
    },
    deploymentStatement: {
      ...fileReference(deploymentBytes, requireArg(args, "deployment-url")),
      signature: fileReference(
        deploymentSignatureBytes,
        requireArg(args, "deployment-signature-url"),
      ),
      environment: deployment.environment,
      deployedAt: deployment.deployedAt,
    },
    web: {
      publicOrigin: manifest.artifacts.web.publicOrigin,
      entryDocumentSha256: manifest.artifacts.web.entryDocumentSha256,
      assetManifestSha256: manifest.artifacts.web.assetManifestSha256,
    },
    evaluator: {
      evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
      encryptionKeyId: manifest.trust.evaluatorEncryption.keyId,
      resultSigningKeyId: manifest.trust.resultSigning.keyId,
      policySigningKeyId: manifest.trust.policySigning.keyId,
      receiptTransparencySigningKeyId: manifest.trust.receiptTransparencySigning.keyId,
      workloadImageDigest: manifest.trust.workload.imageDigest,
      policyMeasurement: manifest.trust.workload.policyMeasurement,
      measurements: manifest.trust.workload.measurements,
      attestationProvider: manifest.trust.workload.attestationProvider,
      attestationClaimPolicy: manifest.trust.workload.attestationClaimPolicy,
      attestationRootFingerprint: manifest.trust.workload.attestationRootFingerprint,
    },
    responseTransparency: {
      protocolVersion: 1,
      logId: "herd-response-log-v1",
      url: httpsUrl(
        args["response-transparency-url"] ??
          new URL("/api/transparency/responses", manifest.artifacts.web.publicOrigin).toString(),
        "response transparency URL",
      ),
      signingKey: manifest.trust.receiptTransparencySigning,
      dataPolicy: "hash-chain-heads-only-v1",
      entryFields: ["entryHash", "head", "logIndex", "previousEntryHash"],
    },
    monitoredResources: deployment.monitoredResources,
    verifier: {
      sourceUrl: httpsUrl(requireArg(args, "verifier-source-url"), "verifier source URL"),
      command: "node release/verify-release-manifest.mjs",
    },
  };
  await writeCanonicalJson(requireArg(args, "output"), output);
  process.stdout.write(`${JSON.stringify({ output: args.output, releaseId: output.releaseId })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
