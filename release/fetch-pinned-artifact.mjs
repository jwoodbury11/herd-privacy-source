#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { Readable } from "node:stream";

import { parseArgs, readJson, requireArg } from "./lib/canonical.mjs";
import { normalizeReleaseManifest } from "./lib/release-manifest.mjs";

function descriptor(manifest, selection) {
  if (selection === "web") return manifest.artifacts.web.deploymentArchive;
  if (selection === "ios") return manifest.artifacts.ios.submissionArchive;
  throw new TypeError("--artifact must be web or ios.");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = normalizeReleaseManifest(await readJson(requireArg(args, "manifest")), {
    requireProduction: true,
  });
  const selected = descriptor(manifest, requireArg(args, "artifact"));
  if (!selected.url) throw new TypeError("Selected production artifact has no public HTTPS URL.");
  const output = path.resolve(requireArg(args, "output"));
  if (path.basename(output) !== selected.name) {
    throw new TypeError("Output filename must equal the signed artifact name.");
  }
  const response = await fetch(selected.url, {
    redirect: "error",
    headers: { accept: selected.mediaType },
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok || !response.body) throw new TypeError(`Artifact download failed with HTTP ${response.status}.`);
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) !== selected.size) {
    throw new TypeError("Artifact Content-Length does not match the signed manifest.");
  }
  await mkdir(path.dirname(output), { recursive: true });
  const temporary = `${output}.tmp-${process.pid}`;
  let size = 0;
  const hash = createHash("sha256");
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.byteLength;
      if (size > selected.size) return callback(new TypeError("Artifact exceeds its signed size."));
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  try {
    await pipeline(Readable.fromWeb(response.body), meter, createWriteStream(temporary, { mode: 0o600 }));
    const sha256 = hash.digest("hex");
    if (size !== selected.size || sha256 !== selected.sha256) {
      throw new TypeError("Downloaded artifact does not match its signed hash and size.");
    }
    await rename(temporary, output);
    process.stdout.write(`${JSON.stringify({ verified: true, artifact: args.artifact, output, sha256, size })}\n`);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
