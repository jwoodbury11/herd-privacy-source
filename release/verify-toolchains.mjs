#!/usr/bin/env node
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { parseArgs, readJson, requireArg } from "./lib/canonical.mjs";

const run = promisify(execFile);

async function command(file, args) {
  const { stdout, stderr } = await run(file, args, { maxBuffer: 1024 * 1024 });
  return `${stdout}${stderr}`.trim();
}

export function verifyToolchainFacts(spec, facts, profile) {
  const failures = [];
  if (facts.node !== spec.release.node) failures.push(`Node ${facts.node} != ${spec.release.node}`);
  if (facts.npm !== spec.release.npm) failures.push(`npm ${facts.npm} != ${spec.release.npm}`);
  if (facts.timezone !== spec.release.timezone) failures.push(`timezone ${facts.timezone} != ${spec.release.timezone}`);
  if (facts.locale !== spec.release.locale) failures.push(`locale ${facts.locale} != ${spec.release.locale}`);
  if (spec.release.sourceDateEpochRequired && !/^(0|[1-9][0-9]*)$/u.test(facts.sourceDateEpoch ?? "")) {
    failures.push("SOURCE_DATE_EPOCH is missing or non-canonical");
  }
  if (profile === "ios") {
    if (facts.xcode !== spec.ios.xcode) failures.push(`Xcode ${facts.xcode} != ${spec.ios.xcode}`);
    if (facts.xcodeBuild !== spec.ios.xcodeBuild) {
      failures.push(`Xcode build ${facts.xcodeBuild} != ${spec.ios.xcodeBuild}`);
    }
    if (facts.swift !== spec.ios.swift) failures.push(`Swift ${facts.swift} != ${spec.ios.swift}`);
    if (facts.sdk !== spec.ios.sdk.replace("iphoneos", "")) {
      failures.push(`iPhoneOS SDK ${facts.sdk} != ${spec.ios.sdk.replace("iphoneos", "")}`);
    }
    if (facts.simulatorSdk !== spec.ios.simulatorSdk.replace("iphonesimulator", "")) {
      failures.push(
        `iPhoneSimulator SDK ${facts.simulatorSdk} != ${spec.ios.simulatorSdk.replace("iphonesimulator", "")}`,
      );
    }
  }
  if (failures.length > 0) throw new TypeError(`Pinned toolchain verification failed:\n- ${failures.join("\n- ")}`);
  return true;
}

async function actualFacts(profile) {
  const facts = {
    node: process.versions.node,
    npm: await command("npm", ["--version"]),
    timezone: process.env.TZ ?? "",
    locale: process.env.LC_ALL ?? process.env.LANG ?? "",
    sourceDateEpoch: process.env.SOURCE_DATE_EPOCH ?? "",
  };
  if (profile === "ios") {
    const xcode = await command("xcodebuild", ["-version"]);
    facts.xcode = xcode.match(/^Xcode (.+)$/mu)?.[1] ?? "";
    facts.xcodeBuild = xcode.match(/^Build version (.+)$/mu)?.[1] ?? "";
    const swift = await command("swift", ["--version"]);
    facts.swift = swift.match(/Apple Swift version ([0-9.]+)/u)?.[1] ?? "";
    facts.sdk = await command("xcrun", ["--sdk", "iphoneos", "--show-sdk-version"]);
    facts.simulatorSdk = await command("xcrun", ["--sdk", "iphonesimulator", "--show-sdk-version"]);
  }
  return facts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const spec = await readJson(requireArg(args, "spec"));
  const profile = args.profile ?? "release";
  if (!['release', 'ios'].includes(profile)) throw new TypeError("--profile must be release or ios.");
  const facts = args.facts ? await readJson(args.facts) : await actualFacts(profile);
  verifyToolchainFacts(spec, facts, profile);
  for (const lockPath of spec.packageLocks) {
    const lock = await readJson(lockPath);
    if (lock.lockfileVersion !== 3) throw new TypeError(`${lockPath} is not lockfileVersion 3.`);
    if (
      lockPath === "monitor/package-lock.json" &&
      lock.packages?.["node_modules/wrangler"]?.version !== spec.monitor.wrangler
    ) {
      throw new TypeError("The monitor lockfile does not contain the pinned Wrangler version.");
    }
  }
  process.stdout.write(`${JSON.stringify({ verified: true, profile, facts })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
