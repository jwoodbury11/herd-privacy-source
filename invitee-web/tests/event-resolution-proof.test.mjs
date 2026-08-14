import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryDirectory = await mkdtemp(join(tmpdir(), "herd-result-proof-"));

after(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

async function transpile(sourceName, outputName, replacements = []) {
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

await transpile("lib/privacy/protocol.ts", "protocol.mjs");
await transpile(
  "lib/privacy/event-resolution-proof.ts",
  "event-resolution-proof.mjs",
  [[/from "\.\/protocol";/u, 'from "./protocol.mjs";']],
);

const protocol = await import(
  `${pathToFileURL(join(temporaryDirectory, "protocol.mjs")).href}?test=1`,
);
const proofModule = await import(
  `${pathToFileURL(join(temporaryDirectory, "event-resolution-proof.mjs")).href}?test=1`,
);

const eventId = "10000000-0000-4000-8000-000000000001";
const inviteeId = "20000000-0000-4000-8000-000000000001";
const relayRequestId = "30000000-0000-4000-8000-000000000001";
const leaseId = "40000000-0000-4000-8000-000000000001";
const evaluatedAt = "2026-08-03T20:00:00.000Z";
const deadline = "2026-08-03T19:59:00.000Z";
const policyHash = protocol.bytesToBase64Url(new Uint8Array(32).fill(0x21));
const batchHash = protocol.bytesToBase64Url(new Uint8Array(32).fill(0x42));
const relayRequestHash = protocol.bytesToBase64Url(new Uint8Array(32).fill(0x63));
const evaluatorKeyId = "evaluator-encryption-2026";
const signingKeyId = "result-signing-2026";

const keyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
const signingPublicKey = protocol.bytesToBase64Url(
  new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
);
const pin = { signingKeyId, signingPublicKey };
const context = {
  eventId,
  rsvpDeadline: deadline,
  privateResponsePolicy: {
    protocolVersion: 1,
    cipherSuite: protocol.PRIVATE_RESPONSE_CIPHER_SUITE,
    policyHash,
    canonicalDocument: "{}",
    evaluatorKeyId,
    evaluatorPublicKey: signingPublicKey,
    evaluatorMeasurement: "sha256:test",
    releaseId: "release-2026",
    paddedPlaintextBytes: 4096,
    frozenAt: deadline,
  },
};

async function signedResolution(status = "confirmed") {
  const result = {
    protocolVersion: 1,
    eventId,
    policyHash,
    batchHash,
    evaluatorKeyId,
    status,
    ...(status === "confirmed" ? { attendingMemberIds: ["host", inviteeId] } : {}),
  };
  const canonicalDocument = JSON.stringify({
    protocolVersion: 1,
    signingKeyId,
    relayRequestHash,
    relayRequestId,
    leaseId,
    evaluatedAt,
    result,
  });
  const signature = protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        new TextEncoder().encode(canonicalDocument),
      ),
    ),
  );
  return {
    status,
    ...(status === "confirmed"
      ? { attendingMemberIds: ["host", inviteeId], attendanceRevealed: true }
      : {}),
    resolvedAt: evaluatedAt,
    attestation: {
      protocolVersion: 1,
      signingKeyId,
      evaluatedAt,
      canonicalDocument,
      signature,
    },
  };
}

test("web accepts only the exact evaluator-signed final result", async () => {
  for (const status of ["confirmed", "not_confirmed"]) {
    const resolution = await signedResolution(status);
    assert.deepEqual(
      await proofModule.verifyEventResolutionProof(context, resolution, pin),
      resolution,
    );
    assert.deepEqual(
      await proofModule.displayableEventResolution(context, resolution, pin),
      resolution,
    );
  }
});

test("web fails closed for legacy results, tampering, and a rotated signing pin", async () => {
  const valid = await signedResolution();
  const mutations = [
    (value) => { delete value.attestation; },
    (value) => { value.status = "not_confirmed"; delete value.attendingMemberIds; },
    (value) => { value.attendingMemberIds = ["host"]; },
    (value) => {
      const document = JSON.parse(value.attestation.canonicalDocument);
      document.result.batchHash = protocol.bytesToBase64Url(new Uint8Array(32).fill(0x99));
      value.attestation.canonicalDocument = JSON.stringify(document);
    },
    (value) => { value.resolvedAt = "2026-08-03T20:00:01.000Z"; },
    (value) => { value.attestation.evaluatedAt = "2026-08-03T20:00:01.000Z"; },
    (value) => { value.attestation.canonicalDocument += " "; },
    (value) => {
      value.attestation.signature = `${value.attestation.signature[0] === "A" ? "B" : "A"}${value.attestation.signature.slice(1)}`;
    },
    (value) => { value.attestation.extra = true; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(valid);
    mutate(changed);
    assert.deepEqual(
      await proofModule.displayableEventResolution(context, changed, pin),
      { status: "verification_unavailable" },
    );
  }

  const nextKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const nextPin = {
    signingKeyId,
    signingPublicKey: protocol.bytesToBase64Url(
      new Uint8Array(await crypto.subtle.exportKey("raw", nextKeyPair.publicKey)),
    ),
  };
  assert.deepEqual(
    await proofModule.displayableEventResolution(context, valid, nextPin),
    { status: "verification_unavailable" },
  );
  assert.deepEqual(
    await proofModule.displayableEventResolution(
      { ...context, eventId: "10000000-0000-4000-8000-000000000002" },
      valid,
      pin,
    ),
    { status: "verification_unavailable" },
  );
});
