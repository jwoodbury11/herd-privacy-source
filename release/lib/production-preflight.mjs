import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";

import { canonicalJson, hashFile } from "./canonical.mjs";
import { verifyLocalArtifacts } from "./artifacts.mjs";
import { verifyProvenanceBundles } from "./provenance-verification.mjs";
import {
  assertProductionConfigurationDigest,
  buildProductionConfig,
} from "./production-config.mjs";
import { PRODUCTION_INSPECTION_LIMIT_BYTES } from "./production-template.mjs";

const FORBIDDEN_BUILD_PATTERNS = [
  { pattern: /herd-evaluator-live-v1/iu, label: "legacy evaluator key ID" },
  { pattern: /jimmy4\.chatgpt\.site/iu, label: "preview deployment URL" },
  {
    pattern:
      /https:\/\/(?:[^\s"'`/]+\.)?(?:localhost|[^\s"'`/]*(?:preview|staging|testing|sandbox)[^\s"'`/]*)/iu,
    label: "non-production URL",
  },
];

function cString(buffer, start, length) {
  const end = buffer.indexOf(0, start);
  return buffer.subarray(start, end === -1 || end > start + length ? start + length : end).toString("utf8");
}

function octal(buffer, start, length, label) {
  const value = cString(buffer, start, length).trim();
  if (!/^[0-7]+$/u.test(value)) throw new TypeError(`Web archive has an invalid ${label}.`);
  const result = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(result)) throw new TypeError(`Web archive ${label} is too large.`);
  return result;
}

export function readUstarFiles(archive) {
  const files = new Map();
  let offset = 0;
  let zeroBlocks = 0;
  while (offset + 512 <= archive.byteLength) {
    const header = archive.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      if (zeroBlocks === 2) break;
      continue;
    }
    if (zeroBlocks !== 0) throw new TypeError("Web archive has data after an isolated zero block.");
    if (cString(header, 257, 6) !== "ustar") throw new TypeError("Web artifact is not a USTAR archive.");
    const storedChecksum = octal(header, 148, 8, "header checksum");
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const actualChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    if (storedChecksum !== actualChecksum) throw new TypeError("Web archive has an invalid header checksum.");
    if (header[156] !== 0x30 && header[156] !== 0) {
      throw new TypeError("Web archive contains an entry that is not a regular file.");
    }
    const name = cString(header, 0, 100);
    const prefix = cString(header, 345, 155);
    const archivePath = prefix ? `${prefix}/${name}` : name;
    if (
      !archivePath ||
      archivePath.startsWith("/") ||
      archivePath.includes("\\") ||
      archivePath.split("/").some((segment) => !segment || segment === "." || segment === "..") ||
      files.has(archivePath)
    ) {
      throw new TypeError("Web archive contains an unsafe or duplicate path.");
    }
    const size = octal(header, 124, 12, "file size");
    if (size > 512 * 1024 * 1024 || offset + size > archive.byteLength) {
      throw new TypeError("Web archive contains an invalid or oversized file.");
    }
    files.set(archivePath, archive.subarray(offset, offset + size));
    offset += Math.ceil(size / 512) * 512;
  }
  if (zeroBlocks !== 2 || offset !== archive.byteLength) {
    throw new TypeError("Web archive must end with exactly two zero blocks.");
  }
  return files;
}

async function compareGeneratedFiles(configDirectory, expectedFiles) {
  const names = (await readdir(configDirectory)).sort();
  const expectedNames = Object.keys(expectedFiles).sort();
  if (
    names.length !== expectedNames.length ||
    names.some((name, index) => name !== expectedNames[index])
  ) {
    throw new TypeError("Generated production configuration directory has missing or unexpected files.");
  }
  for (const name of expectedNames) {
    const filePath = path.join(configDirectory, name);
    const metadata = await lstat(filePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new TypeError(`Generated configuration ${name} is not a regular file.`);
    }
    const actual = await readFile(filePath, "utf8");
    if (actual !== expectedFiles[name]) {
      throw new TypeError(`Generated production configuration ${name} does not match the signed manifest.`);
    }
  }
}

async function verifyArtifact(filePath, descriptor, label) {
  if (path.basename(filePath) !== descriptor.name) {
    throw new TypeError(`${label} filename does not match the signed manifest.`);
  }
  const actual = await hashFile(filePath);
  if (actual.sha256 !== descriptor.sha256 || actual.size !== descriptor.size) {
    throw new TypeError(`${label} does not match the signed manifest hash and size.`);
  }
  return actual;
}

async function readInspectableArchive(filePath, label) {
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new TypeError(`${label} must be a regular, non-symbolic-link file.`);
  }
  if (metadata.size > PRODUCTION_INSPECTION_LIMIT_BYTES) {
    throw new TypeError(
      `${label} exceeds the ${PRODUCTION_INSPECTION_LIMIT_BYTES}-byte production inspection limit.`,
    );
  }
  const bytes = await readFile(filePath);
  if (bytes.byteLength !== metadata.size) throw new TypeError(`${label} changed while it was being read.`);
  return bytes;
}

function requiredWebValues(result) {
  return [
    result.configurationSha256,
    ...Object.values(result.webPublicEnvironment),
  ].map((value) => String(value).replaceAll("\n", "\\n"));
}

function verifyWebArchive(archive, result) {
  const files = readUstarFiles(archive);
  const markerEntries = [...files.entries()].filter(([name]) =>
    name.endsWith("/HERD-RELEASE-CONFIG-SHA256"),
  );
  if (
    markerEntries.length !== 1 ||
    markerEntries[0][1].toString("utf8") !== `${result.configurationSha256}\n`
  ) {
    throw new TypeError("Web archive lacks the exact signed release-configuration marker.");
  }
  const artifactReleaseMarkerEntries = [...files.entries()].filter(([name]) =>
    name.endsWith("/HERD-ARTIFACT-RELEASE-ID"),
  );
  if (
    artifactReleaseMarkerEntries.length !== 1 ||
    artifactReleaseMarkerEntries[0][1].toString("utf8") !==
      `${result.manifest.releaseId}\n`
  ) {
    throw new TypeError("Web archive lacks the exact signed artifact-release marker.");
  }
  const searchable = [...files.values()]
    .filter((bytes) => bytes.byteLength <= 16 * 1024 * 1024 && !bytes.includes(0))
    .map((bytes) => bytes.toString("utf8"))
    .join("\n");
  for (const { pattern, label } of FORBIDDEN_BUILD_PATTERNS) {
    if (pattern.test(searchable)) throw new TypeError(`Web archive contains a ${label}.`);
  }
  for (const required of requiredWebValues(result)) {
    if (!searchable.includes(required)) {
      throw new TypeError("Web archive does not contain every public value derived from the signed manifest.");
    }
  }
}

function verifySchedulerArchive(archive, result) {
  const files = readUstarFiles(archive);
  const expected = result.files["scheduler-runtime-vars.json"];
  const runtimeEntries = [...files.entries()].filter(([name]) =>
    name.endsWith("/scheduler-runtime-vars.json"),
  );
  if (runtimeEntries.length !== 1 || runtimeEntries[0][1].toString("utf8") !== expected) {
    throw new TypeError(
      "Scheduler archive does not embed the exact manifest-derived scheduler runtime variables.",
    );
  }
  const searchable = [...files.values()]
    .filter((bytes) => bytes.byteLength <= 16 * 1024 * 1024 && !bytes.includes(0))
    .map((bytes) => bytes.toString("utf8"))
    .join("\n");
  for (const { pattern, label } of FORBIDDEN_BUILD_PATTERNS) {
    if (pattern.test(searchable)) throw new TypeError(`Scheduler archive contains a ${label}.`);
  }
  for (const value of Object.values(result.schedulerRuntimeVariables)) {
    if (!searchable.includes(String(value))) {
      throw new TypeError("Scheduler archive lacks a manifest-derived runtime value.");
    }
  }
}

function verifyIosInfo(info, result) {
  if (!info || typeof info !== "object" || Array.isArray(info)) {
    throw new TypeError("Processed iOS Info.plist JSON must be an object.");
  }
  for (const [key, expected] of Object.entries(result.iosInfoValues)) {
    if (info[key] !== expected) {
      throw new TypeError(`Processed iOS Info.plist ${key} does not match the signed manifest.`);
    }
  }
  const serialized = canonicalJson(info);
  if (/\$\([^)]+\)/u.test(serialized)) {
    throw new TypeError("Processed iOS Info.plist contains an unresolved build setting.");
  }
  for (const { pattern, label } of FORBIDDEN_BUILD_PATTERNS) {
    if (pattern.test(serialized)) throw new TypeError(`Processed iOS Info.plist contains a ${label}.`);
  }
}

export function verifyIosEntitlements(entitlements, result) {
  if (!entitlements || typeof entitlements !== "object" || Array.isArray(entitlements)) {
    throw new TypeError("Signed iOS entitlements must be a dictionary.");
  }
  const allowed = new Set([
    "application-identifier",
    "beta-reports-active",
    "com.apple.developer.associated-domains",
    "com.apple.developer.team-identifier",
    "get-task-allow",
    "keychain-access-groups",
  ]);
  const unexpected = Object.keys(entitlements).filter((key) => !allowed.has(key));
  if (unexpected.length > 0) {
    throw new TypeError(`Signed iOS entitlements contain an unexpected capability: ${unexpected[0]}.`);
  }
  const expected = result.contract.ios;
  if (entitlements["application-identifier"] !== expected.appIdentifier) {
    throw new TypeError("Signed iOS application-identifier does not match the production app identity.");
  }
  if (entitlements["com.apple.developer.team-identifier"] !== expected.developmentTeam) {
    throw new TypeError("Signed iOS team identifier does not match the production team.");
  }
  if (
    !Array.isArray(entitlements["com.apple.developer.associated-domains"]) ||
    entitlements["com.apple.developer.associated-domains"].length !== 1 ||
    entitlements["com.apple.developer.associated-domains"][0] !== `applinks:${expected.associatedDomain}`
  ) {
    throw new TypeError("Signed iOS associated domains do not contain the exact production universal-link domain.");
  }
  if (
    !Array.isArray(entitlements["keychain-access-groups"]) ||
    entitlements["keychain-access-groups"].length !== 1 ||
    entitlements["keychain-access-groups"][0] !== expected.keychainAccessGroup
  ) {
    throw new TypeError("Signed iOS Keychain access group does not match the production app identity.");
  }
  if (entitlements["get-task-allow"] !== undefined && entitlements["get-task-allow"] !== false) {
    throw new TypeError("Signed production iOS entitlements enable get-task-allow.");
  }
  if (
    entitlements["beta-reports-active"] !== undefined &&
    typeof entitlements["beta-reports-active"] !== "boolean"
  ) {
    throw new TypeError("Signed iOS beta-reports-active entitlement is invalid.");
  }
}

export async function preflightProductionArtifacts({
  manifest,
  evaluatorUrl,
  rootCertificate,
  configDirectory,
  artifactRoot,
  webArchivePath,
  iosArchivePath,
  normalizedIosBinaryPath,
  iosInfo,
  iosEntitlements,
  cosign = "cosign",
}) {
  const result = buildProductionConfig(manifest, { evaluatorUrl, rootCertificate });
  assertProductionConfigurationDigest(result);
  await compareGeneratedFiles(configDirectory, result.files);
  const artifactCount = await verifyLocalArtifacts(result.manifest, artifactRoot);
  const provenanceBundles = await verifyProvenanceBundles(result.manifest, artifactRoot, { cosign });
  await verifyArtifact(webArchivePath, result.manifest.artifacts.web.deploymentArchive, "Web archive");
  await verifyArtifact(iosArchivePath, result.manifest.artifacts.ios.submissionArchive, "iOS archive");
  const normalizedIosBinary = await hashFile(normalizedIosBinaryPath);
  if (normalizedIosBinary.sha256 !== result.manifest.artifacts.ios.normalizedBinarySha256) {
    throw new TypeError("Normalized iOS executable does not match the signed manifest hash.");
  }
  verifyWebArchive(await readInspectableArchive(webArchivePath, "Web archive"), result);
  verifySchedulerArchive(
    await readInspectableArchive(
      path.join(artifactRoot, result.manifest.artifacts.scheduler.name),
      "Scheduler archive",
    ),
    result,
  );
  verifyIosInfo(iosInfo, result);
  verifyIosEntitlements(iosEntitlements, result);
  return {
    releaseId: result.manifest.releaseId,
    configurationSha256: result.configurationSha256,
    webArchiveSha256: result.manifest.artifacts.web.deploymentArchive.sha256,
    iosArchiveSha256: result.manifest.artifacts.ios.submissionArchive.sha256,
    normalizedIosBinarySha256: normalizedIosBinary.sha256,
    iosBundleIdentifier: result.manifest.artifacts.ios.bundleIdentifier,
    iosVersion: result.manifest.artifacts.ios.version,
    iosBuild: result.manifest.artifacts.ios.build,
    artifactCount,
    provenanceBundles,
  };
}
