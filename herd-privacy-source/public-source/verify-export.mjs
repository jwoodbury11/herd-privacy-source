#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import {
  canonicalJson,
  parseArgs,
  readJson,
  requireArg,
  sha256Hex,
} from "../release/lib/canonical.mjs";
import {
  createTarArchive,
  normalizeExportManifest,
  normalizeExportPolicy,
} from "./lib/export-core.mjs";

function cString(buffer, start, length) {
  const field = buffer.subarray(start, start + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString("utf8");
}

function octal(buffer, start, length, label) {
  const text = cString(buffer, start, length).trim();
  if (!/^[0-7]+$/u.test(text)) throw new TypeError(`Invalid USTAR ${label}.`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) throw new TypeError(`Oversized USTAR ${label}.`);
  return value;
}

function parseTar(archive) {
  if (archive.byteLength < 1024 || archive.byteLength % 512 !== 0) {
    throw new TypeError("Public-source archive is not block-aligned USTAR.");
  }
  const entries = [];
  let offset = 0;
  while (offset < archive.byteLength) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      const remainder = archive.subarray(offset);
      if (remainder.byteLength < 1024 || !remainder.every((byte) => byte === 0)) {
        throw new TypeError("Public-source archive has an invalid USTAR terminator.");
      }
      return entries;
    }
    const storedChecksum = octal(header, 148, 8, "checksum");
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const computedChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    if (storedChecksum !== computedChecksum) throw new TypeError("Public-source archive checksum failed.");
    if (cString(header, 257, 6) !== "ustar" || cString(header, 263, 2) !== "00") {
      throw new TypeError("Public-source archive contains a non-USTAR header.");
    }
    if (header[156] !== 0x30 && header[156] !== 0) {
      throw new TypeError("Public-source archive contains a non-regular entry.");
    }
    const name = cString(header, 0, 100);
    const prefix = cString(header, 345, 155);
    const archivePath = prefix ? `${prefix}/${name}` : name;
    const size = octal(header, 124, 12, "size");
    const mode = octal(header, 100, 8, "mode");
    const mtime = octal(header, 136, 12, "mtime");
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > archive.byteLength) throw new TypeError("Public-source archive entry is truncated.");
    entries.push({ archivePath, mode, mtime, bytes: archive.subarray(dataStart, dataEnd) });
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  throw new TypeError("Public-source archive has no USTAR terminator.");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const archivePath = requireArg(args, "archive");
  const manifestPath = requireArg(args, "manifest");
  const policyPath = requireArg(args, "policy");
  const archive = await readFile(archivePath);
  const externalManifestText = await readFile(manifestPath, "utf8");
  const policyBytes = await readFile(policyPath);
  const policy = normalizeExportPolicy(await readJson(policyPath));
  const manifest = normalizeExportManifest(JSON.parse(externalManifestText), policy);
  if (externalManifestText !== canonicalJson(manifest)) {
    throw new TypeError("External public-source manifest is not canonical JSON.");
  }
  if (manifest.policy.sha256 !== sha256Hex(policyBytes)) {
    throw new TypeError("Public-source manifest does not bind the supplied export policy.");
  }
  const entries = parseTar(archive);
  const manifestArchivePath = `${manifest.archivePrefix}/PUBLIC-SOURCE-MANIFEST.json`;
  const archiveManifestEntry = entries.find(({ archivePath: name }) => name === manifestArchivePath);
  if (!archiveManifestEntry || archiveManifestEntry.bytes.toString("utf8") !== externalManifestText) {
    throw new TypeError("Archive and external public-source manifests differ.");
  }
  const expectedPaths = new Set(manifest.files.map(({ path: filePath }) => `${manifest.archivePrefix}/${filePath}`));
  if (
    entries.length !== manifest.files.length + 1 ||
    entries.some(({ archivePath: name }) => name !== manifestArchivePath && !expectedPaths.has(name))
  ) {
    throw new TypeError("Public-source archive contains an unmanifested or missing entry.");
  }
  const files = manifest.files.map((record) => {
    const entry = entries.find(({ archivePath: name }) => name === `${manifest.archivePrefix}/${record.path}`);
    if (
      !entry ||
      entry.mtime !== manifest.sourceDateEpoch ||
      entry.mode !== Number.parseInt(record.mode, 8) ||
      entry.bytes.byteLength !== record.size ||
      sha256Hex(entry.bytes) !== record.sha256
    ) {
      throw new TypeError(`Public-source archive entry failed verification: ${record.path}`);
    }
    return { path: record.path, bytes: entry.bytes, mode: entry.mode };
  });
  const rebuilt = createTarArchive(files, manifest, manifest.sourceDateEpoch);
  if (!rebuilt.equals(archive)) throw new TypeError("Public-source archive is not canonical deterministic USTAR.");
  process.stdout.write(
    `${JSON.stringify({ verified: true, files: files.length, archiveSha256: sha256Hex(archive), size: archive.byteLength })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
