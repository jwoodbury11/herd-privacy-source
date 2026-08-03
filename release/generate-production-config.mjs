#!/usr/bin/env node
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { parseArgs, readJson, requireArg } from "./lib/canonical.mjs";
import {
  assertProductionConfigurationDigest,
  buildProductionConfig,
  IOS_XCCONFIG_NAME,
} from "./lib/production-config.mjs";

async function atomicWrite(filePath, contents) {
  const temporary = `${filePath}.tmp-${process.pid}`;
  await writeFile(temporary, contents, { mode: 0o600 });
  await rename(temporary, filePath);
}

async function main() {
  const args = parseArgs(process.argv.slice(2), {
    boolean: ["prepare", "verify-template"],
  });
  if (args.prepare && args["verify-template"]) {
    throw new TypeError("--prepare and --verify-template are mutually exclusive.");
  }
  const manifestPath = requireArg(args, "manifest");
  const outputDirectory = requireArg(args, "output-directory");
  const evaluatorUrl = requireArg(args, "evaluator-url");
  const rootCertificatePath = requireArg(args, "attestation-root-certificate");
  const result = buildProductionConfig(await readJson(manifestPath), {
    evaluatorUrl,
    rootCertificate: await readFile(rootCertificatePath),
    releaseTemplate: Boolean(args.prepare || args["verify-template"]),
  });
  assertProductionConfigurationDigest(result, { prepare: Boolean(args.prepare) });
  await mkdir(outputDirectory, { recursive: true });
  for (const [name, contents] of Object.entries(result.files)) {
    await atomicWrite(path.join(outputDirectory, name), contents);
  }
  process.stdout.write(
    `${JSON.stringify({
      verified: !args.prepare,
      releaseId: result.manifest.releaseId,
      configurationSha256: result.configurationSha256,
      iosIdentity: result.contract.ios,
      outputDirectory,
      iosXcconfig: path.join(outputDirectory, IOS_XCCONFIG_NAME),
    })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
