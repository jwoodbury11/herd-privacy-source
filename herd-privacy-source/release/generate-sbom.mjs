#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import {
  compareStrings,
  parseArgs,
  readJson,
  requireArg,
  requireString,
  sha256Hex,
  timestampFromEpoch,
  writeCanonicalJson,
} from "./lib/canonical.mjs";

function spdxId(value) {
  const normalized = value.replace(/[^A-Za-z0-9.-]/gu, "-").replace(/-+/gu, "-");
  return `SPDXRef-${normalized.replace(/^-|-$/gu, "") || "item"}`;
}

function checksumFromIntegrity(integrity) {
  if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) return null;
  const bytes = Buffer.from(integrity.slice(7), "base64");
  if (bytes.byteLength !== 64 || `sha512-${bytes.toString("base64")}` !== integrity) return null;
  return { algorithm: "SHA512", checksumValue: bytes.toString("hex") };
}

function declaredLicense(value) {
  if (typeof value !== "string" || !value || value.length > 200) return "NOASSERTION";
  return /^[A-Za-z0-9.+()\-: ]+$/u.test(value) ? value : "NOASSERTION";
}

function packageNameFromPath(packagePath, fallback) {
  if (!packagePath) return fallback;
  const marker = "node_modules/";
  const index = packagePath.lastIndexOf(marker);
  if (index === -1) return fallback;
  const suffix = packagePath.slice(index + marker.length);
  const segments = suffix.split("/");
  return segments[0].startsWith("@") ? `${segments[0]}/${segments[1]}` : segments[0];
}

function purl(name, version) {
  const encodedName = name.startsWith("@")
    ? `${encodeURIComponent(name.split("/")[0])}/${encodeURIComponent(name.split("/")[1])}`
    : encodeURIComponent(name);
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

async function lockPackages(lockPath, lockIndex) {
  const lock = await readJson(lockPath);
  if (lock.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== "object") {
    throw new TypeError(`${lockPath} must be an npm lockfileVersion 3 document.`);
  }
  const root = lock.packages[""];
  const rootName = requireString(root?.name ?? lock.name, `${lockPath} root package name`, { maximum: 214 });
  const rootVersion = requireString(root?.version ?? lock.version, `${lockPath} root package version`, { maximum: 80 });
  const rootId = spdxId(`npm-root-${lockIndex}-${rootName}-${rootVersion}`);
  const packages = [
    {
      SPDXID: rootId,
      name: rootName,
      versionInfo: rootVersion,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: declaredLicense(root?.license),
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: purl(rootName, rootVersion),
        },
      ],
    },
  ];
  const relationships = [];
  const seen = new Set();
  for (const [packagePath, metadata] of Object.entries(lock.packages).sort(([left], [right]) => compareStrings(left, right))) {
    if (!packagePath || !metadata?.version) continue;
    const name = packageNameFromPath(packagePath, metadata.name);
    if (!name) throw new TypeError(`${lockPath} cannot derive a package name for ${packagePath}.`);
    const identity = `${name}@${metadata.version}:${metadata.resolved ?? ""}:${metadata.integrity ?? ""}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    const id = spdxId(`npm-${lockIndex}-${sha256Hex(identity).slice(0, 24)}`);
    const checksum = checksumFromIntegrity(metadata.integrity);
    packages.push({
      SPDXID: id,
      name,
      versionInfo: String(metadata.version),
      downloadLocation:
        typeof metadata.resolved === "string" && metadata.resolved.startsWith("https://")
          ? metadata.resolved
          : "NOASSERTION",
      filesAnalyzed: false,
      ...(checksum ? { checksums: [checksum] } : {}),
      licenseConcluded: "NOASSERTION",
      licenseDeclared: declaredLicense(metadata.license),
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: purl(name, String(metadata.version)),
        },
      ],
    });
    relationships.push({ spdxElementId: rootId, relationshipType: "DEPENDS_ON", relatedSpdxElement: id });
  }
  return { rootId, packages, relationships };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const sourceManifestPath = requireArg(args, "source-manifest");
  const sourceRoot = path.resolve(requireArg(args, "source-root"));
  const outputPath = requireArg(args, "output");
  const name = requireArg(args, "name");
  const lockPaths = Array.isArray(args._) ? args._ : [];
  if (lockPaths.length === 0) {
    throw new TypeError("Pass one or more package-lock paths as positional arguments.");
  }
  const sourceManifest = await readJson(sourceManifestPath);
  if (!Array.isArray(sourceManifest.files) || !Number.isSafeInteger(sourceManifest.sourceDateEpoch)) {
    throw new TypeError("Source manifest is missing files or sourceDateEpoch.");
  }
  const sourcePackageId = "SPDXRef-Package-Herd-Privacy-Source";
  const sourceFileSha1 = [];
  const files = [];
  for (const [index, file] of sourceManifest.files.entries()) {
    if (
      typeof file?.path !== "string" ||
      file.path.startsWith("/") ||
      file.path.split("/").some((segment) => !segment || segment === "." || segment === "..")
    ) {
      throw new TypeError(`Source manifest file ${index} has an unsafe path.`);
    }
    const filePath = path.join(sourceRoot, ...file.path.split("/"));
    const metadata = await lstat(filePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new TypeError(`Source manifest path is not a regular file: ${file.path}`);
    }
    const bytes = await readFile(filePath);
    if (bytes.byteLength !== file.size || sha256Hex(bytes) !== file.sha256) {
      throw new TypeError(`Source file differs from its export manifest: ${file.path}`);
    }
    const sha1 = createHash("sha1").update(bytes).digest("hex");
    sourceFileSha1.push(sha1);
    files.push({
      SPDXID: spdxId(`File-${index}-${file.sha256.slice(0, 16)}`),
      fileName: `./${file.path}`,
      checksums: [
        { algorithm: "SHA1", checksumValue: sha1 },
        { algorithm: "SHA256", checksumValue: file.sha256 },
      ],
      licenseConcluded: "Apache-2.0",
      copyrightText: "NOASSERTION",
    });
  }
  const packageResults = await Promise.all(lockPaths.map((lockPath, index) => lockPackages(lockPath, index)));
  const namespaceSeed = JSON.stringify({
    sourceRevision: sourceManifest.sourceRevision,
    sourceFiles: sourceManifest.files.map(({ path: filePath, sha256 }) => [filePath, sha256]),
    locks: await Promise.all(
      lockPaths.map(async (lockPath) => [path.basename(path.dirname(lockPath)), sha256Hex(await readFile(lockPath))]),
    ),
  });
  const documentId = sha256Hex(namespaceSeed);
  const documentSpdxId = "SPDXRef-DOCUMENT";
  const packages = [
    {
      SPDXID: sourcePackageId,
      name: "herd-privacy-critical-source",
      versionInfo: sourceManifest.sourceRevision,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: true,
      verificationCode: {
        packageVerificationCodeValue: createHash("sha1")
          .update(sourceFileSha1.sort().join(""))
          .digest("hex"),
      },
      licenseConcluded: "Apache-2.0",
      licenseDeclared: "Apache-2.0",
      copyrightText: "NOASSERTION",
    },
    ...packageResults.flatMap(({ packages: lockEntries }) => lockEntries),
  ];
  const relationships = [
    { spdxElementId: documentSpdxId, relationshipType: "DESCRIBES", relatedSpdxElement: sourcePackageId },
    ...packageResults.map(({ rootId }) => ({
      spdxElementId: documentSpdxId,
      relationshipType: "DESCRIBES",
      relatedSpdxElement: rootId,
    })),
    ...files.map(({ SPDXID }) => ({
      spdxElementId: sourcePackageId,
      relationshipType: "CONTAINS",
      relatedSpdxElement: SPDXID,
    })),
    ...packageResults.flatMap(({ relationships: lockRelationships }) => lockRelationships),
  ];
  const sbom = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: documentSpdxId,
    name,
    documentNamespace: `https://spdx.org/spdxdocs/herd-${documentId}`,
    creationInfo: {
      created: timestampFromEpoch(sourceManifest.sourceDateEpoch),
      creators: ["Tool: herd-release-sbom-generator-1"],
      licenseListVersion: "3.26",
    },
    packages: packages.sort((left, right) => compareStrings(left.SPDXID, right.SPDXID)),
    files: files.sort((left, right) => compareStrings(left.fileName, right.fileName)),
    relationships: relationships.sort((left, right) =>
      compareStrings(
        `${left.spdxElementId}:${left.relationshipType}:${left.relatedSpdxElement}`,
        `${right.spdxElementId}:${right.relationshipType}:${right.relatedSpdxElement}`,
      ),
    ),
  };
  await writeCanonicalJson(outputPath, sbom);
  const bytes = await readFile(outputPath);
  process.stdout.write(
    `${JSON.stringify({ output: outputPath, sha256: sha256Hex(bytes), size: bytes.byteLength, packages: packages.length, files: files.length })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
