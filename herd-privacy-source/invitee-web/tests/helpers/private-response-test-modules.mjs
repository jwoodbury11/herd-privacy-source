import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

async function transpile(projectRoot, temporaryDirectory, sourceName, outputName, replacements = []) {
  let source = await readFile(join(projectRoot, sourceName), "utf8");
  for (const [pattern, replacement] of replacements) {
    source = source.replace(pattern, replacement);
  }
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
      isolatedModules: true,
    },
    fileName: sourceName,
  }).outputText;
  await writeFile(join(temporaryDirectory, outputName), output);
}

export async function loadPrivateResponseTestModules(projectRoot) {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), "herd-private-response-vector-"));
  await transpile(projectRoot, temporaryDirectory, "lib/privacy/protocol.ts", "protocol.mjs");
  await transpile(
    projectRoot,
    temporaryDirectory,
    "lib/privacy/trust-verification.ts",
    "trust-verification.mjs",
    [[/from "\.\/protocol";/u, 'from "./protocol.mjs";']],
  );
  await transpile(
    projectRoot,
    temporaryDirectory,
    "lib/privacy/private-response-crypto.ts",
    "private-response-crypto.mjs",
    [
      [/from "\.\/protocol";/u, 'from "./protocol.mjs";'],
      [/from "\.\/trust-verification";/u, 'from "./trust-verification.mjs";'],
    ],
  );

  const nonce = `${process.pid}-${Date.now()}-${Math.random()}`;
  const protocol = await import(
    `${pathToFileURL(join(temporaryDirectory, "protocol.mjs")).href}?${nonce}`
  );
  const trustVerification = await import(
    `${pathToFileURL(join(temporaryDirectory, "trust-verification.mjs")).href}?${nonce}`
  );
  const privateResponseCrypto = await import(
    `${pathToFileURL(join(temporaryDirectory, "private-response-crypto.mjs")).href}?${nonce}`
  );
  return {
    protocol,
    trustVerification,
    privateResponseCrypto,
    cleanup: () => rm(temporaryDirectory, { recursive: true, force: true }),
  };
}
