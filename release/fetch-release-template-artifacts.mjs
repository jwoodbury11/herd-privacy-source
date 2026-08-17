#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import { parseArgs, readJson, requireArg } from "./lib/canonical.mjs";
import {
  normalizeProductionReleaseTemplate,
  productionExternalArtifacts,
} from "./lib/production-template.mjs";

async function fetchArtifact(artifact, outputDirectory) {
  if (!artifact.url) throw new TypeError(`Artifact ${artifact.name} has no HTTPS URL.`);
  if (artifact.size > 1024 * 1024 * 1024) {
    throw new TypeError(`Artifact ${artifact.name} exceeds the 1 GiB release-fetch limit.`);
  }
  const response = await fetch(artifact.url, {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    headers: { accept: artifact.mediaType },
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok || !response.body) {
    throw new TypeError(`Artifact ${artifact.name} returned HTTP ${response.status}.`);
  }
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== artifact.mediaType.toLowerCase()) {
    throw new TypeError(`Artifact ${artifact.name} has content type ${mediaType ?? "missing"}.`);
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) !== artifact.size) {
    throw new TypeError(`Artifact ${artifact.name} Content-Length differs from its descriptor.`);
  }
  const output = path.join(outputDirectory, artifact.name);
  const temporary = `${output}.tmp-${process.pid}`;
  let size = 0;
  const hash = createHash("sha256");
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.byteLength;
      if (size > artifact.size) {
        callback(new TypeError(`Artifact ${artifact.name} exceeds its descriptor size.`));
        return;
      }
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  try {
    await pipeline(Readable.fromWeb(response.body), meter, createWriteStream(temporary, { mode: 0o600 }));
    const sha256 = hash.digest("hex");
    if (size !== artifact.size || sha256 !== artifact.sha256) {
      throw new TypeError(`Artifact ${artifact.name} differs from its descriptor hash or size.`);
    }
    await rename(temporary, output);
    return { name: artifact.name, sha256, size, mediaType };
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const template = normalizeProductionReleaseTemplate(await readJson(requireArg(args, "template")));
  const outputDirectory = path.resolve(requireArg(args, "output-directory"));
  await mkdir(outputDirectory, { recursive: true });
  const results = [];
  for (const artifact of productionExternalArtifacts(template)) {
    results.push(await fetchArtifact(artifact, outputDirectory));
  }
  process.stdout.write(`${JSON.stringify({ verified: true, artifacts: results })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
