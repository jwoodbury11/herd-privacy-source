import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign as nodeSign,
  webcrypto,
} from "node:crypto";
import { readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const TOKEN = "qa-trust-signer-token-0123456789abcdefghijklmnopqrstuvwxyz";
const POLICY_KEY_ID = "herd-qa-policy-test-v1";
const TRANSPARENCY_KEY_ID = "herd-qa-transparency-test-v1";
const EVALUATOR_KEY_ID = "herd-qa-evaluator-test-v1";
const RESULT_KEY_ID = "herd-qa-result-test-v1";
const EVALUATOR_MEASUREMENT = "software-reference-sha384:test-fixture";
const RELEASE_ID = "herd-qa-release-test-v1";
const POLICY_DOMAIN = "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1";
const RECEIPT_DOMAIN = "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1";
const LOG_HEAD_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
const LOG_ENTRY_HASH_DOMAIN = "HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1";
const RESPONSE_AUTHORIZATION_DOMAIN = "HERD-RESPONSE-AUTHORIZATION-V1";
const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");

async function javascriptModules(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await javascriptModules(entryPath)));
    else if (entry.name.endsWith(".js")) files.push(entryPath);
  }
  return files;
}

async function signingFixture() {
  const [evaluator, result, policy, transparency] = await Promise.all([
    subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    ),
    subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    ),
    subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    ),
    subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    ),
  ]);
  return {
    bindings: {
      HERD_DEPLOYMENT_PROFILE: "test",
      HERD_EVALUATOR_TOKEN: TOKEN,
      HERD_EVALUATOR_KEY_ID: EVALUATOR_KEY_ID,
      HERD_EVALUATOR_PRIVATE_KEY_JWK: JSON.stringify(
        await subtle.exportKey("jwk", evaluator.privateKey),
      ),
      HERD_EVALUATOR_MEASUREMENT: EVALUATOR_MEASUREMENT,
      HERD_RELEASE_ID: RELEASE_ID,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: RESULT_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK: JSON.stringify(
        await subtle.exportKey("jwk", result.privateKey),
      ),
      HERD_SOFTWARE_QA_TRUST_SIGNER_ENABLED: "true",
      HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: POLICY_KEY_ID,
      HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK: JSON.stringify(
        await subtle.exportKey("jwk", policy.privateKey),
      ),
      HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: TRANSPARENCY_KEY_ID,
      HERD_EVALUATOR_TRANSPARENCY_SIGNING_PRIVATE_KEY_JWK: JSON.stringify(
        await subtle.exportKey("jwk", transparency.privateKey),
      ),
    },
    evaluator,
    result,
    policy,
    transparency,
  };
}

async function canonicalPolicyDocument(fixture) {
  const evaluatorPublicKey = Buffer.from(
    await subtle.exportKey("raw", fixture.evaluator.publicKey),
  ).toString("base64url");
  return JSON.stringify({
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    event: {
      id: "10000000-0000-4000-8000-000000000001",
      title: "QA trust signer test",
      eventDate: "2026-08-04T12:00:00.000Z",
      endDate: null,
      hostName: "QA Host",
      locationName: "",
      locationAddress: "",
      eventDescription: "",
    },
    members: [{ id: "20000000-0000-4000-8000-000000000001" }],
    hostRules: { minimumParticipants: 2, requiredGroups: [] },
    rsvpDeadline: "2026-08-04T11:00:00.000Z",
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits: {
      maximumParticipants: 2,
      maximumConditionGroups: 1,
      maximumMembersPerGroup: 1,
      paddedPlaintextBytes: 4_096,
    },
    evaluator: {
      keyId: EVALUATOR_KEY_ID,
      publicKey: evaluatorPublicKey,
      measurement: EVALUATOR_MEASUREMENT,
    },
    releaseId: RELEASE_ID,
  });
}

async function serviceFetch(
  pathname,
  body,
  bindings,
  token = TOKEN,
  origin = null,
) {
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  const miniflare = new Miniflare({
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    bindings,
  });
  try {
    const headers = new Headers({ "content-type": "application/json" });
    if (token !== null) headers.set("authorization", `Bearer ${token}`);
    if (origin !== null) headers.set("origin", origin);
    const response = await miniflare.dispatchFetch(
      `https://evaluator.test${pathname}`,
      { method: "POST", headers, body: JSON.stringify(body) },
    );
    const responseBody = await response.arrayBuffer();
    return new Response(responseBody, {
      status: response.status,
      headers: response.headers,
    });
  } finally {
    await miniflare.dispose();
  }
}

function domainPayload(domain, canonicalPayload) {
  return encoder.encode(`${domain}\0${canonicalPayload}`);
}

function signatureBytes(value) {
  return Buffer.from(value, "base64url");
}

async function sha256(value) {
  return Buffer.from(await subtle.digest("SHA-256", encoder.encode(value))).toString(
    "base64url",
  );
}

function responseSigningIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    publicKey: Buffer.from(publicDer.subarray(publicDer.length - 32)).toString(
      "base64url",
    ),
  };
}

const responseIdentity = responseSigningIdentity();

async function receiptPayload(overrides = {}) {
  const hash = (fill) => Buffer.alloc(32, fill).toString("base64url");
  const fields = {
    protocolVersion: 1,
    logId: "herd-response-log-v1",
    logIndex: 7,
    previousEntryHash: hash(1),
    envelopeId: "40000000-0000-4000-8000-000000000001",
    eventId: "10000000-0000-4000-8000-000000000001",
    inviteeId: "20000000-0000-4000-8000-000000000001",
    policyHash: hash(3),
    accountKeyEpochId: "50000000-0000-4000-8000-000000000001",
    revision: 2,
    ciphertextHash: hash(4),
    responseSigningPublicKey: responseIdentity.publicKey,
    committedAt: "2026-08-02T12:00:00.000Z",
    signingKeyId: TRANSPARENCY_KEY_ID,
    ...overrides,
  };
  const authorizationDocument = JSON.stringify({
    protocolVersion: fields.protocolVersion,
    eventId: fields.eventId,
    inviteeId: fields.inviteeId,
    policyHash: fields.policyHash,
    accountKeyEpochId: fields.accountKeyEpochId,
    revision: fields.revision,
    envelopeId: fields.envelopeId,
    ciphertextHash: fields.ciphertextHash,
    responseSigningPublicKey: fields.responseSigningPublicKey,
  });
  const responseSignature =
    overrides.responseSignature ??
    nodeSign(
      null,
      Buffer.from(
        `${RESPONSE_AUTHORIZATION_DOMAIN}\0${authorizationDocument}`,
        "utf8",
      ),
      responseIdentity.privateKey,
    ).toString("base64url");
  const core = {
    protocolVersion: fields.protocolVersion,
    logId: fields.logId,
    logIndex: fields.logIndex,
    previousEntryHash: fields.previousEntryHash,
    envelopeId: fields.envelopeId,
    eventId: fields.eventId,
    inviteeId: fields.inviteeId,
    policyHash: fields.policyHash,
    accountKeyEpochId: fields.accountKeyEpochId,
    revision: fields.revision,
    ciphertextHash: fields.ciphertextHash,
    responseSigningPublicKey: fields.responseSigningPublicKey,
    responseSignature,
    committedAt: fields.committedAt,
  };
  const entryHash =
    overrides.entryHash ??
    (await sha256(`${LOG_ENTRY_HASH_DOMAIN}\0${JSON.stringify(core)}`));
  return JSON.stringify({
    protocolVersion: core.protocolVersion,
    logId: core.logId,
    logIndex: core.logIndex,
    previousEntryHash: core.previousEntryHash,
    entryHash,
    envelopeId: core.envelopeId,
    eventId: core.eventId,
    inviteeId: core.inviteeId,
    policyHash: core.policyHash,
    accountKeyEpochId: core.accountKeyEpochId,
    revision: core.revision,
    ciphertextHash: core.ciphertextHash,
    responseSigningPublicKey: core.responseSigningPublicKey,
    responseSignature: core.responseSignature,
    committedAt: core.committedAt,
    signingKeyId: fields.signingKeyId,
  });
}

test("QA policy signer authenticates, hashes, domain-separates, and signs exactly", async () => {
  const fixture = await signingFixture();
  const canonicalDocument = await canonicalPolicyDocument(fixture);
  const response = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument },
    fixture.bindings,
  );
  assert.equal(response.status, 200);
  const proof = await response.json();
  assert.deepEqual(Object.keys(proof), [
    "protocolVersion",
    "domain",
    "signingKeyId",
    "payloadHash",
    "signature",
  ]);
  assert.equal(proof.protocolVersion, 1);
  assert.equal(proof.domain, POLICY_DOMAIN);
  assert.equal(proof.signingKeyId, POLICY_KEY_ID);
  assert.equal(proof.payloadHash, await sha256(canonicalDocument));
  assert.equal(signatureBytes(proof.signature).length, 64);
  assert.equal(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      fixture.policy.publicKey,
      signatureBytes(proof.signature),
      domainPayload(POLICY_DOMAIN, canonicalDocument),
    ),
    true,
  );
  assert.equal(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      fixture.policy.publicKey,
      signatureBytes(proof.signature),
      domainPayload(POLICY_DOMAIN, `${canonicalDocument} `),
    ),
    false,
  );
  assert.equal(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      fixture.transparency.publicKey,
      signatureBytes(proof.signature),
      domainPayload(POLICY_DOMAIN, canonicalDocument),
    ),
    false,
  );
});

test("QA transparency signer returns independently verifiable receipt and exact log head", async () => {
  const fixture = await signingFixture();
  const canonicalReceiptPayload = await receiptPayload();
  const response = await serviceFetch(
    "/api/v1/sign/transparency",
    { protocolVersion: 1, kind: "append", canonicalReceiptPayload },
    fixture.bindings,
  );
  assert.equal(response.status, 200);
  const proof = await response.json();
  assert.deepEqual(Object.keys(proof), [
    "protocolVersion",
    "kind",
    "signingKeyId",
    "receipt",
    "logHead",
  ]);
  assert.equal(proof.signingKeyId, TRANSPARENCY_KEY_ID);
  assert.equal(proof.receipt.domain, RECEIPT_DOMAIN);
  assert.equal(proof.receipt.payloadHash, await sha256(canonicalReceiptPayload));
  assert.equal(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      fixture.transparency.publicKey,
      signatureBytes(proof.receipt.signature),
      domainPayload(RECEIPT_DOMAIN, canonicalReceiptPayload),
    ),
    true,
  );

  const head = JSON.parse(proof.logHead.canonicalPayload);
  assert.deepEqual(Object.keys(head), [
    "protocolVersion",
    "logId",
    "treeSize",
    "headEntryHash",
    "generatedAt",
    "signingKeyId",
  ]);
  assert.equal(head.treeSize, 7);
  assert.equal(head.headEntryHash, JSON.parse(canonicalReceiptPayload).entryHash);
  assert.equal(head.signingKeyId, TRANSPARENCY_KEY_ID);
  assert.equal(new Date(head.generatedAt).toISOString(), head.generatedAt);
  assert.equal(proof.logHead.domain, LOG_HEAD_DOMAIN);
  assert.equal(proof.logHead.payloadHash, await sha256(proof.logHead.canonicalPayload));
  assert.equal(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      fixture.transparency.publicKey,
      signatureBytes(proof.logHead.signature),
      domainPayload(LOG_HEAD_DOMAIN, proof.logHead.canonicalPayload),
    ),
    true,
  );
});

test("QA signer is absent unless explicitly enabled and fails closed on auth or key reuse", async () => {
  const fixture = await signingFixture();
  const disabled = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    { ...fixture.bindings, HERD_SOFTWARE_QA_TRUST_SIGNER_ENABLED: "false" },
  );
  assert.equal(disabled.status, 404);
  assert.equal((await disabled.json()).error.code, "not_found");

  const production = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    {
      HERD_DEPLOYMENT_PROFILE: "production",
      HERD_SOFTWARE_QA_TRUST_SIGNER_ENABLED: "true",
    },
  );
  assert.equal(production.status, 404);
  assert.equal((await production.json()).error.code, "not_found");

  const unauthorized = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    fixture.bindings,
    "wrong-token-0123456789abcdefghijklmnopqrstuvwxyz",
  );
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).error.code, "unauthorized");

  const unauthorizedBeforeKeyLoading = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    {
      ...fixture.bindings,
      HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK: "not-json",
    },
    "wrong-token-0123456789abcdefghijklmnopqrstuvwxyz",
  );
  assert.equal(unauthorizedBeforeKeyLoading.status, 401);

  const reused = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    {
      ...fixture.bindings,
      HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: POLICY_KEY_ID,
      HERD_EVALUATOR_TRANSPARENCY_SIGNING_PRIVATE_KEY_JWK:
        fixture.bindings.HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK,
    },
  );
  assert.equal(reused.status, 503);
  assert.equal((await reused.json()).error.code, "service_unavailable");

  const resultKeyReusedForPolicy = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    {
      ...fixture.bindings,
      HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK:
        fixture.bindings.HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK,
    },
  );
  assert.equal(resultKeyReusedForPolicy.status, 503);

  const evaluatorIdReusedForPolicy = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: "{}" },
    {
      ...fixture.bindings,
      HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: EVALUATOR_KEY_ID,
    },
  );
  assert.equal(evaluatorIdReusedForPolicy.status, 503);
});

test("QA transparency signer rejects noncanonical, altered, and unsupported receipts", async () => {
  const fixture = await signingFixture();
  const validReceipt = await receiptPayload();
  const altered = JSON.parse(validReceipt);
  altered.signingKeyId = "attacker-key";
  const wrongKey = await serviceFetch(
    "/api/v1/sign/transparency",
    {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: JSON.stringify(altered),
    },
    fixture.bindings,
  );
  assert.equal(wrongKey.status, 400);

  const extra = JSON.parse(validReceipt);
  extra.plaintext = "must never be accepted";
  const unsupported = await serviceFetch(
    "/api/v1/sign/transparency",
    {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: JSON.stringify(extra),
    },
    fixture.bindings,
  );
  assert.equal(unsupported.status, 400);

  const noncanonical = await serviceFetch(
    "/api/v1/sign/transparency",
    {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: `${validReceipt} `,
    },
    fixture.bindings,
  );
  assert.equal(noncanonical.status, 400);

  const invalidAuthorization = await serviceFetch(
    "/api/v1/sign/transparency",
    {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: await receiptPayload({
        responseSignature: Buffer.alloc(64, 6).toString("base64url"),
      }),
    },
    fixture.bindings,
  );
  assert.equal(invalidAuthorization.status, 400);

  const wrongEntryHash = await serviceFetch(
    "/api/v1/sign/transparency",
    {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: await receiptPayload({
        entryHash: Buffer.alloc(32, 9).toString("base64url"),
      }),
    },
    fixture.bindings,
  );
  assert.equal(wrongEntryHash.status, 400);

  const wrongGenesis = await serviceFetch(
    "/api/v1/sign/transparency",
    {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: await receiptPayload({
        logIndex: 1,
        previousEntryHash: Buffer.alloc(32, 1).toString("base64url"),
      }),
    },
    fixture.bindings,
  );
  assert.equal(wrongGenesis.status, 400);
});

test("QA policy signer rejects arbitrary JSON and mismatched frozen release pins", async () => {
  const fixture = await signingFixture();
  const canonicalDocument = await canonicalPolicyDocument(fixture);
  const arbitrary = await serviceFetch(
    "/api/v1/sign/policy",
    { protocolVersion: 1, canonicalDocument: '{"arbitrary":true}' },
    fixture.bindings,
  );
  assert.equal(arbitrary.status, 400);

  for (const mutation of [
    (document) => { document.releaseId = "another-release"; },
    (document) => { document.evaluator.keyId = "another-evaluator"; },
    (document) => { document.evaluator.measurement = "another-measurement"; },
  ]) {
    const document = JSON.parse(canonicalDocument);
    mutation(document);
    const response = await serviceFetch(
      "/api/v1/sign/policy",
      { protocolVersion: 1, canonicalDocument: JSON.stringify(document) },
      fixture.bindings,
    );
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "invalid_request");
  }
});

test("QA signing routes reject browser-origin requests before loading signer keys", async () => {
  const fixture = await signingFixture();
  const bindings = {
    ...fixture.bindings,
    HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK: "not-json",
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_PRIVATE_KEY_JWK: "not-json",
  };
  for (const [pathname, body] of [
    ["/api/v1/sign/policy", { protocolVersion: 1, canonicalDocument: "{}" }],
    [
      "/api/v1/sign/transparency",
      { protocolVersion: 1, kind: "append", canonicalReceiptPayload: "{}" },
    ],
  ]) {
    const response = await serviceFetch(
      pathname,
      body,
      bindings,
      TOKEN,
      "https://browser.example",
    );
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error.code, "forbidden");
  }
});
