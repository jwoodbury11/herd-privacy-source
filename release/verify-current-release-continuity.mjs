#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import {
  canonicalJson,
  exactKeys,
  parseArgs,
  requireArg,
  requireInteger,
  requireSha256,
  requireString,
  sha256Hex,
  writeCanonicalJson,
} from "./lib/canonical.mjs";
import { normalizeProductionReleaseTemplate } from "./lib/production-template.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";
import { verifyReleaseContinuity } from "./lib/release-continuity.mjs";
import { verifyCanonicalArtifact } from "./lib/signature.mjs";

const MANIFEST_TYPE = "application/vnd.herd.release-manifest.v1+json";
const MAX_POINTER_BYTES = 256 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 64 * 1024;

function safeUrl(value, label, { originOnly = false } = {}) {
  requireString(value, label, { maximum: 2048 });
  const url = new URL(value);
  const forbiddenHostname =
    url.hostname === "localhost" ||
    url.hostname.endsWith(".localhost") ||
    url.hostname.endsWith(".local") ||
    url.hostname.endsWith(".internal") ||
    url.hostname.includes(":") ||
    /^\d+(?:\.\d+){3}$/u.test(url.hostname);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    forbiddenHostname ||
    (originOnly && (url.pathname !== "/" || url.search))
  ) {
    throw new TypeError(`${label} must be a safe public HTTPS ${originOnly ? "origin" : "URL"}.`);
  }
  return originOnly ? url.origin : url.toString();
}

async function fetchBytes(url, maximum, label) {
  const response = await fetch(url, {
    method: "GET",
    redirect: "manual",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(20_000),
  });
  if (response.status !== 200) {
    throw new TypeError(`${label} returned HTTP ${response.status}.`);
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    throw new TypeError(`${label} declares an invalid or oversized body.`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > maximum) {
    throw new TypeError(`${label} is empty or oversized.`);
  }
  return bytes;
}

function parseCanonical(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new TypeError(`${label} is not valid UTF-8 JSON.`);
  }
  if (bytes.toString("utf8") !== canonicalJson(value)) {
    throw new TypeError(`${label} is not canonical JSON.`);
  }
  return value;
}

function reference(value, label) {
  exactKeys(value, ["url", "sha256", "size"], label);
  return {
    url: safeUrl(value.url, `${label}.url`),
    sha256: requireSha256(value.sha256, `${label}.sha256`),
    size: requireInteger(value.size, `${label}.size`, {
      minimum: 1,
      maximum: MAX_MANIFEST_BYTES,
    }),
  };
}

async function fetchReference(value, maximum, label) {
  const normalized = reference(value, label);
  if (normalized.size > maximum) throw new TypeError(`${label} is oversized.`);
  const bytes = await fetchBytes(normalized.url, maximum, label);
  if (
    bytes.byteLength !== normalized.size ||
    sha256Hex(bytes) !== normalized.sha256
  ) {
    throw new TypeError(`${label} differs from its public release pointer.`);
  }
  return { ...normalized, bytes };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const origin = safeUrl(requireArg(args, "origin"), "--origin", {
    originOnly: true,
  });
  const template = normalizeProductionReleaseTemplate(
    JSON.parse(await readFile(requireArg(args, "template"), "utf8")),
  );
  if (template.previousRelease === null) {
    throw new TypeError("A successor production release requires previousRelease.");
  }
  const publicKey = await readFile(requireArg(args, "public-key"), "utf8");
  const pointerUrl = new URL("/.well-known/herd-release.json", origin).toString();
  const pointerBytes = await fetchBytes(
    pointerUrl,
    MAX_POINTER_BYTES,
    "current release pointer",
  );
  const pointer = parseCanonical(pointerBytes, "current release pointer");
  exactKeys(
    pointer,
    [
      "schemaVersion",
      "releaseId",
      "previousRelease",
      "protocol",
      "releaseSigningKey",
      "manifest",
      "deploymentStatement",
      "web",
      "evaluator",
      "responseTransparency",
      "monitoredResources",
      "verifier",
    ],
    "current release pointer",
  );
  if (pointer.schemaVersion !== 1) {
    throw new TypeError("Current release pointer schema is unsupported.");
  }
  exactKeys(pointer.manifest, ["url", "sha256", "size", "signature"], "current manifest reference");
  const [manifestFetch, signatureFetch] = await Promise.all([
    fetchReference(
      {
        url: pointer.manifest.url,
        sha256: pointer.manifest.sha256,
        size: pointer.manifest.size,
      },
      MAX_MANIFEST_BYTES,
      "current signed manifest",
    ),
    fetchReference(
      pointer.manifest.signature,
      MAX_SIGNATURE_BYTES,
      "current manifest signature",
    ),
  ]);
  const previousManifest = normalizeReleaseManifest(
    parseCanonical(manifestFetch.bytes, "current signed manifest"),
    {
      requireProduction: true,
      // The already-signed predecessor predates the split between the runtime
      // image digest and the stable policy measurement. Its original bytes are
      // still verified below; this only supplies the legacy semantic mapping.
      allowLegacyWorkloadPolicy: true,
    },
  );
  if (
    previousManifest.releaseId !== pointer.releaseId ||
    canonicalJson(previousManifest.trust.releaseManifestSigning) !==
      canonicalJson(pointer.releaseSigningKey)
  ) {
    throw new TypeError(
      "Current release pointer does not bind the signed manifest identity.",
    );
  }
  verifyCanonicalArtifact({
    bytes: manifestFetch.bytes,
    envelope: parseCanonical(signatureFetch.bytes, "current manifest signature"),
    publicKey,
    artifactType: MANIFEST_TYPE,
    expectedKey: previousManifest.trust.releaseManifestSigning,
  });
  const continuity = verifyReleaseContinuity(previousManifest, template, {
    previousManifestSha256: manifestFetch.sha256,
  });
  const output = {
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    currentReleasePointer: {
      url: pointerUrl,
      sha256: sha256Hex(pointerBytes),
    },
    previousManifest: {
      releaseId: previousManifest.releaseId,
      url: manifestFetch.url,
      sha256: manifestFetch.sha256,
      signatureUrl: signatureFetch.url,
      signatureSha256: signatureFetch.sha256,
    },
    continuity,
  };
  await writeCanonicalJson(requireArg(args, "output"), output);
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
