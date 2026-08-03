#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { parseArgs, readJson, requireArg, requireInteger, requireString, sha256Hex, writeCanonicalJson } from "./lib/canonical.mjs";

function entries(bundle) {
  const direct = bundle?.verificationMaterial?.tlogEntries;
  if (Array.isArray(direct)) return direct;
  const legacy = bundle?.verificationMaterial?.tlogEntries ?? bundle?.tlogEntries;
  return Array.isArray(legacy) ? legacy : [];
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bundlePath = requireArg(args, "bundle");
  const bundleBytes = await readFile(bundlePath);
  const bundle = await readJson(bundlePath);
  const tlogEntries = entries(bundle);
  if (tlogEntries.length !== 1) {
    throw new TypeError("Sigstore bundle must contain exactly one transparency-log entry.");
  }
  const entry = tlogEntries[0];
  const logId = entry?.logId?.keyId ?? entry?.logId;
  const logIndex = Number(entry?.logIndex);
  const integratedTime = Number(entry?.integratedTime);
  const baseUrl = new URL(requireArg(args, "rekor-record-base-url"));
  if (baseUrl.protocol !== "https:" || baseUrl.username || baseUrl.password || baseUrl.hash) {
    throw new TypeError("Rekor record base URL must be safe HTTPS.");
  }
  const normalizedLogId = requireString(logId, "transparency log ID", { maximum: 256 });
  requireInteger(logIndex, "transparency log index", { minimum: 0 });
  requireInteger(integratedTime, "transparency integrated time", { minimum: 1 });
  baseUrl.searchParams.set("logIndex", String(logIndex));
  const record = {
    provider: "sigstore-rekor",
    logId: normalizedLogId,
    entryId: `${normalizedLogId}:${logIndex}`,
    integratedTime,
    bundleSha256: sha256Hex(bundleBytes),
    url: baseUrl.toString(),
  };
  await writeCanonicalJson(requireArg(args, "output"), record);
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
