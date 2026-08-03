#!/usr/bin/env node
import path from "node:path";
import { readFile } from "node:fs/promises";

import {
  canonicalJson,
  parseArgs,
  readJson,
  requireArg,
  requireString,
  sha256Hex,
  writeCanonicalJson,
} from "./lib/canonical.mjs";
import { artifactReference } from "./lib/artifacts.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";
import {
  normalizeProductionReleaseTemplate,
  PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME,
  PRODUCTION_RELEASE_CONTINUITY_NAME,
  productionProvenanceArtifacts,
} from "./lib/production-template.mjs";

function evidenceUrl(baseValue, name) {
  const base = new URL(baseValue);
  if (
    base.protocol !== "https:" ||
    base.username ||
    base.password ||
    base.hash ||
    base.search ||
    !base.pathname.endsWith("/")
  ) {
    throw new TypeError("--evidence-base-url must be a safe HTTPS directory URL ending in slash.");
  }
  return new URL(encodeURIComponent(name), base).toString();
}

function statementSubjects(statement) {
  if (
    statement?._type !== "https://in-toto.io/Statement/v1" ||
    statement?.predicateType !== "https://slsa.dev/provenance/v1" ||
    !Array.isArray(statement.subject) ||
    statement.subject.length === 0
  ) {
    throw new TypeError("Generated provenance is not a SLSA v1 in-toto statement.");
  }
  const subjects = statement.subject.map((subject) => {
    if (
      !subject ||
      typeof subject !== "object" ||
      Array.isArray(subject) ||
      Object.keys(subject).sort().join(",") !== "digest,name" ||
      !subject.digest ||
      typeof subject.digest !== "object" ||
      Array.isArray(subject.digest) ||
      Object.keys(subject.digest).join(",") !== "sha256" ||
      typeof subject.name !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/u.test(subject.name) ||
      typeof subject.digest.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/u.test(subject.digest.sha256)
    ) {
      throw new TypeError("Generated provenance contains an invalid subject.");
    }
    return { name: subject.name, sha256: subject.digest.sha256 };
  });
  subjects.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  if (new Set(subjects.map(({ name }) => name)).size !== subjects.length) {
    throw new TypeError("Generated provenance contains duplicate subject names.");
  }
  return subjects;
}

function exactSubjectCoverage(subjects, template) {
  const required = productionProvenanceArtifacts(template)
    .map(({ name, sha256 }) => ({ name, sha256 }))
    .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  if (canonicalJson(subjects) !== canonicalJson(required)) {
    throw new TypeError("Generated provenance does not exactly cover every required release artifact.");
  }
}

async function transitionDescriptor(filePath, expectedName, mediaType, evidenceBaseUrl) {
  if (path.basename(filePath) !== expectedName) {
    throw new TypeError(`Transition evidence must be named ${expectedName}.`);
  }
  return artifactReference(filePath, {
    mediaType,
    url: evidenceUrl(evidenceBaseUrl, expectedName),
  });
}

async function canonicalTransition(filePath, label) {
  const text = await readFile(filePath, "utf8");
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new TypeError(`${label} is not valid JSON.`);
  }
  if (text !== canonicalJson(value)) throw new TypeError(`${label} is not canonical JSON.`);
  return value;
}

function canonicalBase64(value, label, { minimumBytes = 1, exactBytes } = {}) {
  if (typeof value !== "string") throw new TypeError(`${label} is not base64.`);
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.byteLength < minimumBytes ||
    (exactBytes !== undefined && bytes.byteLength !== exactBytes) ||
    bytes.toString("base64") !== value
  ) {
    throw new TypeError(`${label} is not canonical base64.`);
  }
  return bytes;
}

function validateInclusionMaterial(entry, logIndex) {
  const signedEntryTimestamp = entry.inclusionPromise?.signedEntryTimestamp;
  const inclusionProof = entry.inclusionProof;
  if (signedEntryTimestamp !== undefined) {
    canonicalBase64(signedEntryTimestamp, "Sigstore signed entry timestamp", {
      minimumBytes: 32,
    });
  }
  if (inclusionProof !== undefined) {
    const proofIndex =
      typeof inclusionProof?.logIndex === "string" &&
      /^(?:0|[1-9][0-9]*)$/u.test(inclusionProof.logIndex)
        ? Number(inclusionProof.logIndex)
        : inclusionProof?.logIndex;
    const treeSize =
      typeof inclusionProof?.treeSize === "string" &&
      /^(?:0|[1-9][0-9]*)$/u.test(inclusionProof.treeSize)
        ? Number(inclusionProof.treeSize)
        : inclusionProof?.treeSize;
    if (
      !Number.isSafeInteger(proofIndex) ||
      proofIndex !== logIndex ||
      !Number.isSafeInteger(treeSize) ||
      treeSize <= logIndex ||
      !Array.isArray(inclusionProof.hashes) ||
      typeof inclusionProof.checkpoint?.envelope !== "string" ||
      inclusionProof.checkpoint.envelope.length === 0
    ) {
      throw new TypeError("Sigstore inclusion proof does not bind the Rekor index and tree.");
    }
    canonicalBase64(inclusionProof.rootHash, "Sigstore inclusion-proof root hash", {
      exactBytes: 32,
    });
    for (const [index, hash] of inclusionProof.hashes.entries()) {
      canonicalBase64(hash, `Sigstore inclusion-proof hash ${index}`, { exactBytes: 32 });
    }
  }
  if (signedEntryTimestamp === undefined && inclusionProof === undefined) {
    throw new TypeError("Sigstore bundle lacks Rekor inclusion material.");
  }
}

function validateBundle(bundle, bundleBytes, statementSha256, transparency) {
  if (
    typeof bundle?.mediaType !== "string" ||
    !/^application\/vnd\.dev\.sigstore\.bundle(?:\.v[0-9]+(?:\.[0-9]+)*)?\+json$/u.test(
      bundle.mediaType,
    )
  ) {
    throw new TypeError("Cosign output is not a supported Sigstore JSON bundle.");
  }
  const digest = bundle.messageSignature?.messageDigest;
  if (!digest || !["SHA2_256", "sha256"].includes(digest.algorithm)) {
    throw new TypeError("Sigstore bundle does not declare a SHA-256 message digest.");
  }
  const digestBytes = canonicalBase64(digest.digest, "Sigstore bundle message digest", {
    exactBytes: 32,
  });
  const boundDigest = digestBytes.toString("hex");
  if (boundDigest !== statementSha256) {
    throw new TypeError("Sigstore bundle does not sign the generated provenance statement.");
  }
  const entries = bundle.verificationMaterial?.tlogEntries;
  if (!Array.isArray(entries) || entries.length !== 1) {
    throw new TypeError("Sigstore bundle must contain exactly one Rekor entry.");
  }
  const entry = entries[0];
  const logId = entry?.logId?.keyId ?? entry?.logId;
  const numeric = (value) =>
    typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value) ? Number(value) : value;
  const logIndex = numeric(entry?.logIndex);
  const integratedTime = numeric(entry?.integratedTime);
  let recordUrl;
  try {
    recordUrl = new URL(transparency.url);
  } catch {
    throw new TypeError("Canonical Rekor record URL is invalid.");
  }
  const query = [...recordUrl.searchParams.entries()];
  if (
    transparency.provider !== "sigstore-rekor" ||
    !Number.isSafeInteger(logIndex) ||
    logIndex < 0 ||
    !Number.isSafeInteger(integratedTime) ||
    integratedTime < 1 ||
    logId !== transparency.logId ||
    transparency.entryId !== `${logId}:${logIndex}` ||
    integratedTime !== transparency.integratedTime ||
    transparency.bundleSha256 !== sha256Hex(bundleBytes) ||
    recordUrl.protocol !== "https:" ||
    recordUrl.username ||
    recordUrl.password ||
    recordUrl.hash ||
    recordUrl.origin !== "https://rekor.sigstore.dev" ||
    recordUrl.pathname !== "/api/v1/log/entries" ||
    query.length !== 1 ||
    query[0][0] !== "logIndex" ||
    query[0][1] !== String(logIndex)
  ) {
    throw new TypeError("Sigstore bundle and canonical Rekor record do not identify the same inclusion.");
  }
  if (
    typeof bundle.verificationMaterial?.certificate?.rawBytes !== "string" ||
    typeof bundle.messageSignature?.signature !== "string" ||
    typeof entry.canonicalizedBody !== "string"
  ) {
    throw new TypeError("Sigstore bundle lacks its signing certificate, signature, or Rekor body.");
  }
  canonicalBase64(bundle.verificationMaterial.certificate.rawBytes, "Sigstore certificate", {
    minimumBytes: 64,
  });
  canonicalBase64(bundle.messageSignature.signature, "Sigstore message signature", {
    minimumBytes: 32,
  });
  validateInclusionMaterial(entry, logIndex);
  const canonicalBody = canonicalBase64(entry.canonicalizedBody, "Sigstore Rekor body");
  if (
    !canonicalBody.toString("utf8").includes(statementSha256)
  ) {
    throw new TypeError("Sigstore Rekor body does not canonically bind the provenance statement digest.");
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const template = normalizeProductionReleaseTemplate(await readJson(requireArg(args, "template")));
  const evidenceBaseUrl = requireArg(args, "evidence-base-url");
  const transitionDescriptors = [
    await transitionDescriptor(
      requireArg(args, "evaluator-epoch-transition"),
      PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME,
      "application/vnd.herd.evaluator-epoch-transition.v2+json",
      evidenceBaseUrl,
    ),
  ];
  const evaluatorTransition = await canonicalTransition(
    requireArg(args, "evaluator-epoch-transition"),
    "Evaluator epoch transition evidence",
  );
  if (
    evaluatorTransition.schemaVersion !== 2 ||
    evaluatorTransition.nextEvaluatorKeyEpochId !== template.evaluatorKeyEpochId
  ) {
    throw new TypeError(
      "Evaluator epoch transition evidence is unrelated to the release template.",
    );
  }
  if (template.previousRelease === null) {
    if (args["release-continuity"]) {
      throw new TypeError("Bootstrap manifest must not include release-continuity evidence.");
    }
  } else {
    const releaseContinuityPath = requireArg(args, "release-continuity");
    const releaseContinuity = await canonicalTransition(
      releaseContinuityPath,
      "Release continuity evidence",
    );
    if (
      releaseContinuity.schemaVersion !== 1 ||
      releaseContinuity.previousManifest?.releaseId !==
        template.previousRelease.releaseId ||
      releaseContinuity.previousManifest?.sha256 !==
        template.previousRelease.manifestSha256 ||
      releaseContinuity.continuity?.previousReleaseId !==
        template.previousRelease.releaseId ||
      releaseContinuity.continuity?.nextReleaseId !== template.releaseId
    ) {
      throw new TypeError(
        "Release continuity evidence is unrelated to the release template.",
      );
    }
    transitionDescriptors.push(
      await transitionDescriptor(
        releaseContinuityPath,
        PRODUCTION_RELEASE_CONTINUITY_NAME,
        "application/vnd.herd.release-continuity.v1+json",
        evidenceBaseUrl,
      ),
    );
  }
  const manifest = structuredClone(template);
  manifest.evidence.transitions = transitionDescriptors;
  const statementPath = requireArg(args, "provenance-statement");
  const bundlePath = requireArg(args, "sigstore-bundle");
  const statementText = await readFile(statementPath, "utf8");
  const statement = JSON.parse(statementText);
  if (statementText !== canonicalJson(statement)) {
    throw new TypeError("Generated provenance statement is not canonical JSON.");
  }
  const subjects = statementSubjects(statement);
  exactSubjectCoverage(subjects, manifest);
  const parameters = statement.predicate?.buildDefinition?.externalParameters;
  if (
    parameters?.releaseId !== template.releaseId ||
    parameters?.source?.repository !== template.source.repository ||
    parameters?.source?.revision !== template.source.revision
  ) {
    throw new TypeError("Generated provenance build parameters are unrelated to the release template.");
  }
  const bundleBytes = await readFile(bundlePath);
  const bundle = JSON.parse(bundleBytes.toString("utf8"));
  const transparency = await readJson(requireArg(args, "transparency-record"));
  validateBundle(bundle, bundleBytes, sha256Hex(Buffer.from(statementText)), transparency);
  const issuer = requireArg(args, "issuer");
  if (issuer !== "https://token.actions.githubusercontent.com") {
    throw new TypeError("Production provenance issuer must be GitHub Actions OIDC.");
  }
  const workflowIdentity = requireString(
    requireArg(args, "workflow-identity"),
    "workflow identity",
    { maximum: 500 },
  );
  const statementDescriptor = await artifactReference(statementPath, {
    mediaType: "application/vnd.in-toto+json",
    url: evidenceUrl(evidenceBaseUrl, path.basename(statementPath)),
  });
  const bundleDescriptor = await artifactReference(bundlePath, {
    mediaType: bundle.mediaType,
    url: evidenceUrl(evidenceBaseUrl, path.basename(bundlePath)),
  });
  manifest.evidence.provenance = [
    {
      subjects,
      predicateType: "https://slsa.dev/provenance/v1",
      issuer,
      workflowIdentity,
      statement: statementDescriptor,
      bundle: bundleDescriptor,
    },
  ];
  manifest.evidence.transparency = [transparency];
  const normalized = normalizeReleaseManifest(manifest, { requireProduction: true });
  await writeCanonicalJson(requireArg(args, "output"), normalized);
  process.stdout.write(
    `${JSON.stringify({
      output: args.output,
      releaseId: normalized.releaseId,
      subjects: subjects.length,
      statementSha256: statementDescriptor.sha256,
      bundleSha256: bundleDescriptor.sha256,
    })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
