import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryDirectory = await mkdtemp(join(tmpdir(), "herd-ballot-identifiers-"));

after(async () => rm(temporaryDirectory, { recursive: true, force: true }));

async function transpile(sourceName, outputName, replacements = []) {
  let source = await readFile(join(projectRoot, sourceName), "utf8");
  for (const [pattern, replacement] of replacements) source = source.replace(pattern, replacement);
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    fileName: sourceName,
  }).outputText;
  await writeFile(join(temporaryDirectory, outputName), output);
}

await transpile("lib/backend/crypto.ts", "crypto.mjs");
await transpile(
  "lib/backend/ballot-identifiers.ts",
  "ballot-identifiers.mjs",
  [
    [/import type \{ HerdBindings \} from "@\/db";\n/u, ""],
    [/from "\.\/crypto";/u, 'from "./crypto.mjs";'],
    [
      /import \{ ApiError \} from "\.\/http";\n/u,
      "class ApiError extends Error { constructor(_status, _code, message) { super(message); } }\n",
    ],
  ],
);

const { deriveBallotId, deriveBallotMemberId } = await import(
  new URL(`file://${join(temporaryDirectory, "ballot-identifiers.mjs")}`)
);

test("ballot pseudonyms are deterministic, event-scoped, and domain-separated", async () => {
  const bindings = {
    HERD_BALLOT_PSEUDONYM_KEY: "test-only-high-entropy-ballot-key",
    HERD_AUTH_PEPPER: "unrelated-auth-pepper",
  };
  const eventA = "11111111-1111-4111-8111-111111111111";
  const eventB = "22222222-2222-4222-8222-222222222222";
  const invitee = "33333333-3333-4333-8333-333333333333";
  const first = await deriveBallotId(bindings, eventA, invitee);
  const second = await deriveBallotId(bindings, eventA, invitee);
  assert.equal(first, second);
  assert.notEqual(first, await deriveBallotId(bindings, eventB, invitee));
  assert.notEqual(first, await deriveBallotMemberId(bindings, eventA, invitee));
  assert.equal(first.length, 43);
  assert.ok(!first.includes(eventA));
  assert.ok(!first.includes(invitee));
});

test("deployed ballot pseudonyms fail closed without their dedicated key", async () => {
  await assert.rejects(
    deriveBallotId(
      {
        HERD_DEPLOYMENT_PROFILE: "production",
        HERD_AUTH_PEPPER: "an-authentication-pepper-that-must-not-be-reused",
      },
      "11111111-1111-4111-8111-111111111111",
      "33333333-3333-4333-8333-333333333333",
    ),
    /ballot pseudonym key is not configured/i,
  );
});
