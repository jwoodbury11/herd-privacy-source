#!/usr/bin/env node

import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const MAXIMUM_TOTAL_BYTES = 512 * 1024 * 1024;

async function regularFiles(target, root = target) {
  const status = await lstat(target);
  if (status.isSymbolicLink()) {
    throw new Error(`Refusing to scan symbolic link: ${path.relative(root, target) || target}`);
  }
  if (status.isFile()) return [target];
  if (!status.isDirectory()) return [];
  const entries = await readdir(target, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const child = path.join(target, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`Refusing to scan symbolic link: ${path.relative(root, child)}`);
    }
    if (entry.isDirectory()) files.push(...(await regularFiles(child, root)));
    else if (entry.isFile()) files.push(child);
  }
  return files;
}

function variants(value) {
  const raw = Buffer.from(value, "utf8");
  const json = JSON.stringify(value).slice(1, -1);
  const encoded = [
    ["raw", raw],
    ["json-escaped", Buffer.from(json, "utf8")],
    ["url-encoded", Buffer.from(encodeURIComponent(value), "utf8")],
    ["base64", Buffer.from(raw.toString("base64"), "ascii")],
    ["base64url", Buffer.from(raw.toString("base64url"), "ascii")],
  ];
  const seen = new Set();
  return encoded.filter(([, bytes]) => {
    if (bytes.length === 0) return false;
    const key = bytes.toString("hex");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function scanSensitiveArtifacts({
  targets,
  sentinels,
  rejectReadableResponseFields = false,
}) {
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new TypeError("At least one artifact path is required.");
  }
  if (!Array.isArray(sentinels) || sentinels.some((value) => typeof value !== "string")) {
    throw new TypeError("Sentinels must be strings.");
  }
  const normalizedSentinels = sentinels.filter((value) => value.length >= 8);
  if (normalizedSentinels.length !== sentinels.length) {
    throw new TypeError("Each privacy sentinel must contain at least eight characters.");
  }
  const needles = normalizedSentinels.flatMap((sentinel, sentinelIndex) =>
    variants(sentinel).map(([encoding, bytes]) => ({
      sentinelIndex,
      encoding,
      bytes,
    })),
  );
  const files = [];
  for (const target of targets) files.push(...(await regularFiles(path.resolve(target))));
  let scannedBytes = 0;
  const findings = [];
  const readableFieldPattern = /(?:["'`]?)(?:reply|answer|minimum_participants|condition_groups|required_groups)(?:["'`]?)\s*(?::|=)/giu;
  for (const file of files) {
    const bytes = await readFile(file);
    scannedBytes += bytes.length;
    if (scannedBytes > MAXIMUM_TOTAL_BYTES) {
      throw new Error("The requested artifact scan exceeds 512 MiB.");
    }
    for (const needle of needles) {
      if (bytes.indexOf(needle.bytes) !== -1) {
        findings.push({
          path: file,
          kind: "sentinel",
          sentinelIndex: needle.sentinelIndex,
          encoding: needle.encoding,
        });
      }
    }
    if (rejectReadableResponseFields) {
      const text = bytes.toString("utf8");
      for (const match of text.matchAll(readableFieldPattern)) {
        findings.push({
          path: file,
          kind: "readable-response-field",
          field: match[0].replace(/\s*(?::|=).*$/u, "").replace(/["'`]/gu, ""),
        });
      }
    }
  }
  return { files: files.length, scannedBytes, findings };
}

function parseCli(arguments_) {
  const targets = [];
  let rejectReadableResponseFields = false;
  let sentinelEnvironment = "HERD_PRIVACY_SENTINELS";
  for (let index = 0; index < arguments_.length; index += 1) {
    const value = arguments_[index];
    if (value === "--reject-readable-response-fields") {
      rejectReadableResponseFields = true;
    } else if (value === "--sentinel-env") {
      sentinelEnvironment = arguments_[index + 1] ?? "";
      index += 1;
    } else if (value.startsWith("-")) {
      throw new Error(`Unknown option: ${value}`);
    } else {
      targets.push(value);
    }
  }
  if (!/^[A-Z][A-Z0-9_]{0,100}$/u.test(sentinelEnvironment)) {
    throw new Error("The sentinel environment-variable name is invalid.");
  }
  const rawSentinels = process.env[sentinelEnvironment] ?? "";
  const sentinels = rawSentinels
    .split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
  return { targets, sentinels, rejectReadableResponseFields };
}

const isCli = process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isCli) {
  try {
    const result = await scanSensitiveArtifacts(parseCli(process.argv.slice(2)));
    if (result.findings.length > 0) {
      for (const finding of result.findings) {
        const detail = finding.kind === "sentinel"
          ? `privacy sentinel ${finding.sentinelIndex + 1} (${finding.encoding})`
          : `readable private-response field ${finding.field}`;
        process.stderr.write(`${finding.path}: ${detail}\n`);
      }
      process.exitCode = 1;
    } else {
      process.stdout.write(
        `Sensitive-artifact scan passed (${result.files} files, ${result.scannedBytes} bytes).\n`,
      );
    }
  } catch (error) {
    process.stderr.write(`Sensitive-artifact scan failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
