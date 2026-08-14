import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import { createEvaluatorApp } from "../src/app.mjs";
import { StatefulTransparencyAuthority } from "../src/transparency-authority.mjs";
import { completeClientRelayEvaluation } from "./vendor/invitee-relay-completion.mjs";
import {
  InMemoryTransparencyStore,
  evaluationRequest,
  makeKeyStore,
  publicKeyFromMetadata,
  testConfig,
  TOKEN,
} from "./helpers.mjs";

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const RELAY_PLAINTEXT_BYTES = 320 * 1024;
const RELAY_CIPHERTEXT_BYTES = 12 + RELAY_PLAINTEXT_BYTES + 16;
const RELAY_KEY_LABEL = "HERD-EVALUATOR-RELAY-KEY-V1\0";
const RELAY_AAD_LABEL = "HERD-EVALUATOR-RELAY-AAD-V1\0";
const RELAY_CAPABILITY_LABEL = "HERD-EVALUATOR-RELAY-CAPABILITY-V1\0";
const RELAY_REQUEST_ID = "60000000-0000-4000-8000-000000000001";
const LEASE_ID = "70000000-0000-4000-8000-000000000001";
const NOW = new Date("2026-01-01T00:00:00.000Z");

function concatenate(...values) {
  const output = new Uint8Array(
    values.reduce((total, value) => total + value.length, 0),
  );
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function ownedArrayBuffer(value) {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

function relayContext(request) {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
  });
}

function capabilityDocument(request) {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
    ciphertext: request.ciphertext,
  });
}

function normalizedRelayDocument(request) {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
    ciphertext: request.ciphertext,
    capabilityMac: request.capabilityMac,
  });
}

async function sha256Base64Url(value) {
  return Buffer.from(
    await subtle.digest("SHA-256", encoder.encode(value)),
  ).toString("base64url");
}

async function deriveRelayKey(sharedSecret, salt, info) {
  const baseKey = await subtle.importKey(
    "raw",
    ownedArrayBuffer(sharedSecret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: ownedArrayBuffer(salt),
      info: ownedArrayBuffer(info),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
}

async function sealRelayRequest({ config, keyStore, token = TOKEN }) {
  const inner = {
    protocolVersion: 1,
    relayRequestId: RELAY_REQUEST_ID,
    leaseId: LEASE_ID,
    issuedAt: "2025-12-31T23:59:30.000Z",
    expiresAt: "2026-01-01T00:01:00.000Z",
    evaluationRequest: await evaluationRequest(config, keyStore),
  };
  const innerBytes = encoder.encode(JSON.stringify(inner));
  assert.ok(innerBytes.length <= 256 * 1024);
  const frame = new Uint8Array(RELAY_PLAINTEXT_BYTES);
  new DataView(frame.buffer).setUint32(0, innerBytes.length, false);
  frame.set(innerBytes, 4);

  const evaluatorPublicKey = await subtle.importKey(
    "raw",
    Buffer.from(
      keyStore.metadata.keys.responseDecryption.publicKey,
      "base64url",
    ),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ephemeralKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const ephemeralPublicKey = new Uint8Array(
    await subtle.exportKey("raw", ephemeralKeyPair.publicKey),
  );
  const salt = webcrypto.getRandomValues(new Uint8Array(32));
  const request = {
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    evaluatorKeyId: keyStore.metadata.keys.responseDecryption.keyId,
    ephemeralPublicKey: Buffer.from(ephemeralPublicKey).toString("base64url"),
    salt: Buffer.from(salt).toString("base64url"),
    ciphertext: "",
    capabilityMac: "",
  };
  const sharedSecret = new Uint8Array(
    await subtle.deriveBits(
      { name: "ECDH", public: evaluatorPublicKey },
      ephemeralKeyPair.privateKey,
      256,
    ),
  );
  const context = encoder.encode(relayContext(request));
  const relayKey = await deriveRelayKey(
    sharedSecret,
    salt,
    concatenate(encoder.encode(RELAY_KEY_LABEL), context),
  );
  sharedSecret.fill(0);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertextAndTag = new Uint8Array(
    await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: ownedArrayBuffer(iv),
        additionalData: ownedArrayBuffer(
          concatenate(encoder.encode(RELAY_AAD_LABEL), context),
        ),
        tagLength: 128,
      },
      relayKey,
      frame,
    ),
  );
  frame.fill(0);
  request.ciphertext = Buffer.from(
    concatenate(iv, ciphertextAndTag),
  ).toString("base64url");
  assert.equal(
    Buffer.from(request.ciphertext, "base64url").length,
    RELAY_CIPHERTEXT_BYTES,
  );
  const capabilityKey = await subtle.importKey(
    "raw",
    encoder.encode(token),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  request.capabilityMac = Buffer.from(
    await subtle.sign(
      "HMAC",
      capabilityKey,
      concatenate(
        encoder.encode(RELAY_CAPABILITY_LABEL),
        encoder.encode(capabilityDocument(request)),
      ),
    ),
  ).toString("base64url");
  return { inner, request };
}

async function harness() {
  const config = testConfig();
  const keyStore = await makeKeyStore(config);
  const transparencyAuthority = new StatefulTransparencyAuthority({
    store: new InMemoryTransparencyStore(),
    keyStore,
    clock: () => new Date(NOW),
  });
  return {
    config,
    keyStore,
    transparencyAuthority,
    app: createEvaluatorApp({
      config,
      keyStore,
      clock: () => new Date(NOW),
      attestationProvider: { async attest() { return "unused"; } },
      transparencyAuthority,
    }),
  };
}

async function freezeEvaluationPolicy(transparencyAuthority, request) {
  const document = JSON.parse(request.policy.canonicalDocument);
  await transparencyAuthority.freezePolicy({
    protocolVersion: 1,
    eventId: request.eventId,
    policyHash: request.policy.policyHash,
    rsvpDeadline: document.rsvpDeadline,
    memberIds: document.members.map(({ id }) => id),
    releaseId: request.policy.releaseId,
    evaluatorKeyId: request.policy.evaluatorKeyId,
  });
}

function relayPost(request, origin) {
  return new Request("https://evaluator.test/api/v1/relay/", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin,
    },
    body: JSON.stringify(request),
  });
}

class CompletionDatabase {
  constructor(row) {
    this.row = structuredClone(row);
  }

  prepare(sql) {
    const database = this;
    return {
      values: [],
      bind(...values) {
        this.values = values;
        return this;
      },
      async first() {
        assert.match(sql, /FROM event_resolutions/u);
        return structuredClone(database.row);
      },
      async run() {
        if (sql.includes("INSERT OR IGNORE INTO event_resolutions")) {
          return { meta: { changes: 0 } };
        }
        assert.match(sql, /UPDATE event_resolutions/u);
        assert.equal(this.values[9], database.row.eventId);
        assert.equal(this.values[10], database.row.policyHash);
        assert.equal(this.values[11], database.row.batchHash);
        assert.equal(this.values[12], database.row.evaluationRequestHash);
        assert.equal(this.values[13], database.row.evaluationLeaseId);
        database.row.status = this.values[0];
        database.row.attendingMemberIds = this.values[1];
        database.row.resolvedAt = this.values[2];
        database.row.resultAttestationProtocolVersion = this.values[3];
        database.row.resultAttestationSigningKeyId = this.values[4];
        database.row.resultAttestationEvaluatedAt = this.values[5];
        database.row.resultAttestationCanonicalDocument = this.values[6];
        database.row.resultAttestationSignature = this.values[7];
        database.row.evaluationLeaseId = null;
        database.row.evaluationLeaseExpiresAt = null;
        database.row.updatedAt = this.values[8];
        return { meta: { changes: 1 } };
      },
    };
  }
}

test("relay response is accepted unmodified by the invitee-web completion contract", async () => {
  const { app, config, keyStore, transparencyAuthority } = await harness();
  const fixture = await sealRelayRequest({ config, keyStore });
  await freezeEvaluationPolicy(
    transparencyAuthority,
    fixture.inner.evaluationRequest,
  );
  const response = await app(relayPost(fixture.request, config.allowedOrigin));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(
    response.headers.get("access-control-allow-origin"),
    config.allowedOrigin,
  );
  const value = await response.json();

  // These are the exact structural, canonical-document, and signature checks
  // performed by invitee-web completeClientRelayEvaluation before persistence.
  assert.deepEqual(Object.keys(value), [
    "protocolVersion",
    "relayRequestHash",
    "relayRequestId",
    "leaseId",
    "result",
    "attestation",
  ]);
  const relayRequestHash = await sha256Base64Url(
    normalizedRelayDocument(fixture.request),
  );
  assert.equal(value.protocolVersion, 1);
  assert.equal(value.relayRequestHash, relayRequestHash);
  assert.equal(value.relayRequestId, RELAY_REQUEST_ID);
  assert.equal(value.leaseId, LEASE_ID);
  assert.deepEqual(value.result, {
    protocolVersion: 1,
    eventId: fixture.inner.evaluationRequest.eventId,
    policyHash: fixture.inner.evaluationRequest.policy.policyHash,
    batchHash: fixture.inner.evaluationRequest.batchHash,
    evaluatorKeyId: fixture.inner.evaluationRequest.policy.evaluatorKeyId,
    revealAttendance: true,
    status: "not_confirmed",
  });
  assert.deepEqual(Object.keys(value.attestation), [
    "protocolVersion",
    "signingKeyId",
    "evaluatedAt",
    "canonicalDocument",
    "signature",
  ]);
  assert.equal(value.attestation.protocolVersion, 1);
  assert.equal(
    value.attestation.signingKeyId,
    keyStore.metadata.keys.evaluationResultSigning.keyId,
  );
  assert.equal(value.attestation.evaluatedAt, NOW.toISOString());
  const canonicalDocument = JSON.stringify({
    protocolVersion: 1,
    signingKeyId: keyStore.metadata.keys.evaluationResultSigning.keyId,
    relayRequestHash,
    relayRequestId: RELAY_REQUEST_ID,
    leaseId: LEASE_ID,
    evaluatedAt: NOW.toISOString(),
    result: value.result,
  });
  assert.equal(value.attestation.canonicalDocument, canonicalDocument);
  const signingPublicKey = await publicKeyFromMetadata(
    keyStore.metadata.keys.evaluationResultSigning,
  );
  assert.equal(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingPublicKey,
      Buffer.from(value.attestation.signature, "base64url"),
      encoder.encode(value.attestation.canonicalDocument),
    ),
    true,
  );

  const policyDocument = JSON.parse(
    fixture.inner.evaluationRequest.policy.canonicalDocument,
  );
  const policy = {
    ...fixture.inner.evaluationRequest.policy,
    policySigningKeyId: null,
    policySignature: null,
  };
  const completionNow = "2026-01-01T00:00:05.000Z";
  const database = new CompletionDatabase({
    eventId: fixture.inner.evaluationRequest.eventId,
    policyHash: policy.policyHash,
    status: "evaluating",
    batchHash: fixture.inner.evaluationRequest.batchHash,
    attendingMemberIds: null,
    resolvedAt: null,
    evaluationLeaseId: LEASE_ID,
    evaluationLeaseExpiresAt: fixture.inner.expiresAt,
    evaluationRequestHash: relayRequestHash,
    resultAttestationProtocolVersion: null,
    resultAttestationSigningKeyId: null,
    resultAttestationEvaluatedAt: null,
    resultAttestationCanonicalDocument: null,
    resultAttestationSignature: null,
    createdAt: "2025-12-31T23:59:00.000Z",
    updatedAt: "2025-12-31T23:59:30.000Z",
  });
  const unchanged = structuredClone(value);
  const completion = await completeClientRelayEvaluation(
    database,
    {
      HERD_DEPLOYMENT_PROFILE: "test",
      HERD_EVALUATOR_TRANSPORT: "client_relay",
      HERD_EVALUATOR_URL: "https://evaluator.test/api/v1/relay/",
      HERD_EVALUATOR_TOKEN: TOKEN,
      HERD_EVALUATOR_KEY_ID:
        keyStore.metadata.keys.responseDecryption.keyId,
      HERD_EVALUATOR_PUBLIC_KEY:
        keyStore.metadata.keys.responseDecryption.publicKey,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID:
        keyStore.metadata.keys.evaluationResultSigning.keyId,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY:
        keyStore.metadata.keys.evaluationResultSigning.publicKey,
    },
    {
      id: fixture.inner.evaluationRequest.eventId,
      invitationsSent: true,
      rsvpDeadline: policyDocument.rsvpDeadline,
      privateResponsePolicy: policy,
    },
    value,
    completionNow,
  );
  assert.deepEqual(value, unchanged, "invitee-web must consume the response as-is");
  assert.deepEqual(completion, {
    status: "not_confirmed",
    resolvedAt: NOW.toISOString(),
    attestation: value.attestation,
  });
});

test("relay capability uses the encrypted request-authentication token and no bearer header", async () => {
  const { app, config, keyStore, transparencyAuthority } = await harness();
  const wrong = await sealRelayRequest({
    config,
    keyStore,
    token: "different-capability-token-000000000000000000000001",
  });
  const rejected = await app(relayPost(wrong.request, config.allowedOrigin));
  assert.equal(rejected.status, 401);
  assert.deepEqual(await rejected.json(), { error: { code: "unauthorized" } });

  const accepted = await sealRelayRequest({ config, keyStore });
  await freezeEvaluationPolicy(
    transparencyAuthority,
    accepted.inner.evaluationRequest,
  );
  const response = await app(relayPost(accepted.request, config.allowedOrigin));
  assert.equal(response.status, 200);
});

test("relay browser preflight preserves the existing narrow CORS contract", async () => {
  const { app, config } = await harness();
  const accepted = await app(
    new Request("https://evaluator.test/api/v1/relay/", {
      method: "OPTIONS",
      headers: {
        origin: config.allowedOrigin,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type, cache-control",
      },
    }),
  );
  assert.equal(accepted.status, 204);
  assert.equal(
    accepted.headers.get("access-control-allow-origin"),
    config.allowedOrigin,
  );
  const rejected = await app(
    new Request("https://evaluator.test/api/v1/relay/", {
      method: "OPTIONS",
      headers: {
        origin: config.allowedOrigin,
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization, content-type",
      },
    }),
  );
  assert.equal(rejected.status, 403);
});
