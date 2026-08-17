#!/usr/bin/env node
import { lstat, mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { tarEntry } from "../public-source/lib/export-core.mjs";
import {
  canonicalJson,
  parseArgs,
  requireArg,
  requireInteger,
  requireString,
  sha256Hex,
  timestampFromEpoch,
  writeCanonicalJson,
} from "./lib/canonical.mjs";

function safeName(value) {
  return requireString(value, "artifact name", {
    maximum: 120,
    pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
  });
}

async function collect(root, current = "") {
  const directory = path.join(root, ...current.split("/").filter(Boolean));
  const children = await readdir(directory);
  children.sort();
  const files = [];
  for (const child of children) {
    const relativePath = current ? `${current}/${child}` : child;
    const absolutePath = path.join(root, ...relativePath.split("/"));
    const metadata = await lstat(absolutePath);
    if (metadata.isSymbolicLink()) throw new TypeError(`Artifact directory contains a symbolic link: ${relativePath}`);
    if (metadata.isDirectory()) {
      files.push(...(await collect(root, relativePath)));
      continue;
    }
    if (!metadata.isFile()) throw new TypeError(`Artifact directory contains a non-regular file: ${relativePath}`);
    if (metadata.size > 512 * 1024 * 1024) throw new TypeError(`Artifact file exceeds 512 MiB: ${relativePath}`);
    const bytes = await readFile(absolutePath);
    files.push({
      path: relativePath,
      bytes,
      mode: metadata.mode & 0o111 ? 0o755 : 0o644,
    });
  }
  return files;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const input = path.resolve(requireArg(args, "input"));
  const output = path.resolve(requireArg(args, "output"));
  const manifestPath = path.resolve(requireArg(args, "manifest"));
  const name = safeName(requireArg(args, "name"));
  const sourceDateEpoch = requireInteger(Number(requireArg(args, "source-date-epoch")), "source date epoch", {
    maximum: 253402300799,
  });
  const files = await collect(input);
  if (files.length === 0) throw new TypeError("Artifact directory is empty.");
  const manifest = {
    schemaVersion: 1,
    artifactName: name,
    archiveFormat: "ustar",
    createdAt: timestampFromEpoch(sourceDateEpoch),
    sourceDateEpoch,
    files: files.map((file) => ({
      path: file.path,
      mode: file.mode.toString(8).padStart(4, "0"),
      size: file.bytes.byteLength,
      sha256: sha256Hex(file.bytes),
    })),
  };
  const parts = files.map((file) =>
    tarEntry(`${name}/${file.path}`, file.bytes, file.mode, sourceDateEpoch),
  );
  parts.push(
    tarEntry(
      `${name}/ARTIFACT-MANIFEST.json`,
      Buffer.from(canonicalJson(manifest)),
      0o644,
      sourceDateEpoch,
    ),
    Buffer.alloc(1024),
  );
  const archive = Buffer.concat(parts);
  await mkdir(path.dirname(output), { recursive: true });
  const temporary = `${output}.tmp-${process.pid}`;
  await writeFile(temporary, archive, { mode: 0o600 });
  await rename(temporary, output);
  await writeCanonicalJson(manifestPath, manifest);
  process.stdout.write(
    `${JSON.stringify({ output, manifest: manifestPath, sha256: sha256Hex(archive), size: archive.byteLength, files: files.length })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
