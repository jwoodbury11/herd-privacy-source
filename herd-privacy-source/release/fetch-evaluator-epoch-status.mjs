#!/usr/bin/env node
import { writeFile } from "node:fs/promises";

import { canonicalJson, parseArgs, requireArg } from "./lib/canonical.mjs";

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const rawOrigin = requireArg(args, "origin");
  const token = process.env.HERD_SCHEDULER_TOKEN;
  let origin;
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
    origin = value.origin;
  } catch {
    throw new TypeError("--origin must be a safe production HTTPS origin.");
  }
  if (
    typeof token !== "string" ||
    token.length < 32 ||
    token.length > 512 ||
    !/^[A-Za-z0-9_-]+$/u.test(token)
  ) {
    throw new TypeError("HERD_SCHEDULER_TOKEN is missing or invalid.");
  }
  const response = await fetch(
    new URL("/api/internal/evaluator-epoch-status", origin),
    {
      method: "POST",
      redirect: "manual",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
      },
      signal: AbortSignal.timeout(20_000),
    },
  );
  if (response.status !== 200) {
    throw new TypeError(`Evaluator epoch status returned HTTP ${response.status}.`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > 32 * 1024) {
    throw new TypeError("Evaluator epoch status is empty or oversized.");
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    bytes.fill(0);
  }
  await writeFile(requireArg(args, "output"), canonicalJson(value), {
    mode: 0o600,
    flag: "wx",
  });
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
