#!/usr/bin/env node
import { parseArgs, requireArg } from "./lib/canonical.mjs";
import { verifyStableLiveReadiness } from "./lib/live-readiness.mjs";

const MAX_RESPONSE_BYTES = 32 * 1024;

function productionOrigin(rawOrigin) {
  try {
    const value = new URL(rawOrigin);
    if (
      value.protocol !== "https:" ||
      value.username ||
      value.password ||
      value.hash ||
      value.search ||
      value.pathname !== "/"
    ) {
      throw new TypeError();
    }
    return value.origin;
  } catch {
    throw new TypeError("--origin must be a safe production HTTPS origin.");
  }
}

function schedulerToken() {
  const token = process.env.HERD_SCHEDULER_TOKEN;
  if (
    typeof token !== "string" ||
    token.length < 32 ||
    token.length > 512 ||
    !/^[A-Za-z0-9_-]+$/u.test(token)
  ) {
    throw new TypeError("HERD_SCHEDULER_TOKEN is missing or invalid.");
  }
  return token;
}

async function fetchSample(origin, token, index) {
  const url = new URL("/api/internal/release-readiness", origin);
  url.searchParams.set("sample", `${Date.now()}-${index}`);
  const response = await fetch(url, {
    method: "POST",
    redirect: "manual",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "cache-control": "no-store",
    },
    signal: AbortSignal.timeout(20_000),
  });
  if (response.status !== 200) {
    throw new TypeError(`Live readiness sample ${index + 1} returned HTTP ${response.status}.`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > MAX_RESPONSE_BYTES) {
    throw new TypeError(`Live readiness sample ${index + 1} is empty or oversized.`);
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    bytes.fill(0);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const origin = productionOrigin(requireArg(args, "origin"));
  const count = args.samples === undefined ? 12 : Number(args.samples);
  if (!Number.isInteger(count) || count < 2 || count > 50) {
    throw new TypeError("--samples must be an integer from 2 through 50.");
  }
  const token = schedulerToken();
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    samples.push(await fetchSample(origin, token, index));
  }
  const result = verifyStableLiveReadiness(samples, {
    artifactReleaseId: args["artifact-release-id"],
    workloadImageDigest: args["evaluator-image-digest"],
  });
  process.stdout.write(`${JSON.stringify({ ...result, samples: count })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
