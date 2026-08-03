#!/usr/bin/env node
import { execFile, spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { chmod, copyFile, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { promisify } from "node:util";

import { parseArgs, requireArg } from "./lib/canonical.mjs";

const run = promisify(execFile);

function safeZipEntries(stdout) {
  const entries = stdout.split(/\r?\n/u).filter(Boolean);
  if (entries.length === 0 || new Set(entries).size !== entries.length) {
    throw new TypeError("iOS archive has no entries or contains duplicate entries.");
  }
  for (const entry of entries) {
    if (
      entry.startsWith("/") ||
      entry.includes("\\") ||
      entry.includes("\0") ||
      entry.split("/").some((segment) => segment === "." || segment === "..")
    ) {
      throw new TypeError("iOS archive contains an unsafe path.");
    }
  }
  return entries;
}

async function unzipSmallEntry(archive, entry) {
  const { stdout } = await run("/usr/bin/unzip", ["-p", archive, entry], {
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024,
  });
  return stdout;
}

async function unzipEntryToFile(archive, entry, output) {
  const child = spawn("/usr/bin/unzip", ["-p", archive, entry], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 64 * 1024) stderr += chunk.slice(0, 64 * 1024 - stderr.length);
  });
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code === 0) resolve();
      else {
        reject(
          new TypeError(
            `Could not extract the iOS application executable (exit ${code ?? "unknown"}${signal ? `, signal ${signal}` : ""}): ${stderr.trim()}`,
          ),
        );
      }
    });
  });
  try {
    await Promise.all([
      pipeline(child.stdout, createWriteStream(output, { flags: "wx", mode: 0o700 })),
      completion,
    ]);
    await chmod(output, 0o700);
  } catch (error) {
    child.kill();
    await rm(output, { force: true });
    throw error;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const archive = path.resolve(requireArg(args, "archive"));
  const outputDirectory = path.resolve(requireArg(args, "output-directory"));
  const { stdout } = await run("/usr/bin/unzip", ["-Z1", archive], {
    maxBuffer: 16 * 1024 * 1024,
  });
  const entries = safeZipEntries(stdout);
  const infoEntries = entries.filter((entry) => /^Payload\/[^/]+\.app\/Info\.plist$/u.test(entry));
  if (infoEntries.length !== 1) {
    throw new TypeError("iOS archive must contain exactly one top-level application Info.plist.");
  }
  await mkdir(outputDirectory, { recursive: true });
  const plistPath = path.join(outputDirectory, "Info.plist");
  const infoJsonPath = path.join(outputDirectory, "Info.plist.json");
  await writeFile(plistPath, await unzipSmallEntry(archive, infoEntries[0]), { mode: 0o600 });
  await run("/usr/bin/plutil", ["-convert", "json", "-o", infoJsonPath, plistPath], {
    maxBuffer: 1024 * 1024,
  });
  const info = JSON.parse(await readFile(infoJsonPath, "utf8"));
  if (
    typeof info.CFBundleExecutable !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/u.test(info.CFBundleExecutable)
  ) {
    throw new TypeError("iOS archive has an invalid CFBundleExecutable.");
  }
  const appPrefix = infoEntries[0].slice(0, -"Info.plist".length);
  const executableEntry = `${appPrefix}${info.CFBundleExecutable}`;
  if (!entries.includes(executableEntry)) throw new TypeError("iOS application executable is missing.");
  const executablePath = path.join(outputDirectory, "HerdHost.executable");
  const normalizedPath = path.join(outputDirectory, "HerdHost.normalized-executable");
  await unzipEntryToFile(archive, executableEntry, executablePath);
  try {
    await run("/usr/bin/codesign", ["--verify", "--strict", executablePath], {
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    throw new TypeError(
      `The iOS executable signature is invalid: ${error instanceof Error ? error.message : error}`,
    );
  }
  const entitlementsPlistPath = path.join(outputDirectory, "Entitlements.plist");
  const entitlementsJsonPath = path.join(outputDirectory, "Entitlements.plist.json");
  let signedEntitlements;
  try {
    ({ stdout: signedEntitlements } = await run(
      "/usr/bin/codesign",
      ["-d", "--entitlements", "-", executablePath],
      { encoding: "buffer", maxBuffer: 4 * 1024 * 1024 },
    ));
  } catch (error) {
    throw new TypeError(
      `Signed iOS entitlements could not be extracted: ${error instanceof Error ? error.message : error}`,
    );
  }
  if (!signedEntitlements?.byteLength) {
    throw new TypeError("The signed iOS executable contains no entitlements.");
  }
  await writeFile(entitlementsPlistPath, signedEntitlements, { mode: 0o600 });
  await run("/usr/bin/plutil", ["-convert", "json", "-o", entitlementsJsonPath, entitlementsPlistPath], {
    maxBuffer: 1024 * 1024,
  });
  const temporary = `${normalizedPath}.tmp-${process.pid}`;
  await copyFile(executablePath, temporary);
  await chmod(temporary, 0o700);
  try {
    await run("/usr/bin/codesign", ["--remove-signature", temporary], {
      maxBuffer: 1024 * 1024,
    });
    await rename(temporary, normalizedPath);
  } catch (error) {
    await rm(temporary, { force: true });
    throw new TypeError(
      `The iOS executable could not be normalized by removing its code signature: ${error instanceof Error ? error.message : error}`,
    );
  }
  process.stdout.write(
    `${JSON.stringify({
      verified: true,
      infoJson: infoJsonPath,
      entitlementsJson: entitlementsJsonPath,
      normalizedExecutable: normalizedPath,
    })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
