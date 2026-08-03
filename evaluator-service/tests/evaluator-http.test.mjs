import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const TOKEN = "test-evaluator-token-with-more-than-32-characters";
const KEY_ID = "herd-evaluator-test-v1";
const MEASUREMENT = "software-reference-evaluator-test-sha384";
const RELEASE_ID = "herd-test-release-v1";
const EVENT_ID = "10000000-0000-4000-8000-000000000001";
const INVITEE_A = "20000000-0000-4000-8000-000000000001";
const INVITEE_B = "20000000-0000-4000-8000-000000000002";
const HOST_GROUP = "30000000-0000-4000-8000-000000000001";
const RESPONSE_GROUP = "30000000-0000-4000-8000-000000000002";
const PROTOCOL_VERSION = 1;
const CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM";
const PADDED_PLAINTEXT_BYTES = 4_096;
const PAYLOAD_FRAME_BYTES = 4_124;
const USER_WRAP_BYTES = 60;
const EVALUATOR_WRAP_BYTES = 157;
const RELAY_ORIGIN = "https://herd-invitee.test";
const RESULT_SIGNING_KEY_ID = "herd-evaluator-result-test-v1";
const RELAY_PLAINTEXT_BYTES = 320 * 1024;
const RELAY_CIPHERTEXT_BYTES = 12 + RELAY_PLAINTEXT_BYTES + 16;
const RELAY_KEY_LABEL = "HERD-EVALUATOR-RELAY-KEY-V1\0";
const RELAY_AAD_LABEL = "HERD-EVALUATOR-RELAY-AAD-V1\0";
const RELAY_CAPABILITY_LABEL = "HERD-EVALUATOR-RELAY-CAPABILITY-V1\0";
const RESPONSE_AUTHORIZATION_LABEL = "HERD-RESPONSE-AUTHORIZATION-V1\0";
const RELAY_REQUEST_ID = "60000000-0000-4000-8000-000000000001";
const LEASE_ID = "70000000-0000-4000-8000-000000000001";

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

async function createHarness(bindings) {
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  return new Miniflare({
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    bindings,
  });
}

function concatenate(...values) {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function arrayBuffer(value) {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function derElement(tag, value) {
  assert.ok(value.length < 128);
  return Buffer.concat([Buffer.from([tag, value.length]), Buffer.from(value)]);
}

function sec1Pem(privateJwk) {
  const privateScalar = Buffer.from(privateJwk.d, "base64url");
  const publicPoint = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(privateJwk.x, "base64url"),
    Buffer.from(privateJwk.y, "base64url"),
  ]);
  const curveOid = derElement(
    0x06,
    Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
  );
  const body = Buffer.concat([
    derElement(0x02, Buffer.from([0x01])),
    derElement(0x04, privateScalar),
    derElement(0xa0, curveOid),
    derElement(0xa1, derElement(0x03, Buffer.concat([Buffer.from([0]), publicPoint]))),
  ]);
  const encoded = derElement(0x30, body).toString("base64");
  const lines = encoded.match(/.{1,64}/gu);
  assert.ok(lines);
  return `-----BEGIN EC PRIVATE KEY-----\n${lines.join("\n")}\n-----END EC PRIVATE KEY-----`;
}

async function sha256(value) {
  return base64Url(
    new Uint8Array(await subtle.digest("SHA-256", encoder.encode(value))),
  );
}

function envelopeCommitmentDocument(envelope) {
  return JSON.stringify({
    protocolVersion: envelope.protocolVersion,
    cipherSuite: envelope.cipherSuite,
    envelopeId: envelope.envelopeId,
    eventId: envelope.eventId,
    inviteeId: envelope.inviteeId,
    policyHash: envelope.policyHash,
    revision: envelope.revision,
    accountKeyEpochId: envelope.accountKeyEpochId,
    evaluatorKeyId: envelope.evaluatorKeyId,
    payloadCiphertext: envelope.payloadCiphertext,
    userKeyWrap: envelope.userKeyWrap,
    evaluatorKeyWrap: envelope.evaluatorKeyWrap,
    responseSigningPublicKey: envelope.responseSigningPublicKey,
  });
}

async function envelopeCommitmentHash(envelope) {
  return sha256(envelopeCommitmentDocument(envelope));
}

async function authorizeEnvelope(envelope) {
  const signingKeyPair = await subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  envelope.responseSigningPublicKey = base64Url(
    new Uint8Array(await subtle.exportKey("raw", signingKeyPair.publicKey)),
  );
  const ciphertextHash = await envelopeCommitmentHash(envelope);
  const canonicalDocument = JSON.stringify({
    protocolVersion: envelope.protocolVersion,
    eventId: envelope.eventId,
    inviteeId: envelope.inviteeId,
    policyHash: envelope.policyHash,
    accountKeyEpochId: envelope.accountKeyEpochId,
    revision: envelope.revision,
    envelopeId: envelope.envelopeId,
    ciphertextHash,
    responseSigningPublicKey: envelope.responseSigningPublicKey,
  });
  envelope.responseSignature = base64Url(
    new Uint8Array(
      await subtle.sign(
        { name: "Ed25519" },
        signingKeyPair.privateKey,
        encoder.encode(`${RESPONSE_AUTHORIZATION_LABEL}${canonicalDocument}`),
      ),
    ),
  );
  return ciphertextHash;
}

function uuidBytes(value) {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}

function envelopeContext(envelope) {
  const value = new Uint8Array(101);
  let offset = 0;
  value[offset] = PROTOCOL_VERSION;
  offset += 1;
  for (const bytes of [
    uuidBytes(envelope.eventId),
    uuidBytes(envelope.inviteeId),
    new Uint8Array(Buffer.from(envelope.policyHash, "base64url")),
    uuidBytes(envelope.envelopeId),
    uuidBytes(envelope.accountKeyEpochId),
  ]) {
    value.set(bytes, offset);
    offset += bytes.length;
  }
  new DataView(value.buffer).setUint32(offset, envelope.revision, false);
  return value;
}

function labeled(label, envelope) {
  return concatenate(
    encoder.encode(label),
    new Uint8Array([0]),
    envelopeContext(envelope),
  );
}

async function sealAesFrame(key, plaintext, aad) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertextAndTag = new Uint8Array(
    await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: arrayBuffer(iv),
        additionalData: arrayBuffer(aad),
        tagLength: 128,
      },
      key,
      arrayBuffer(plaintext),
    ),
  );
  return concatenate(iv, ciphertextAndTag);
}

async function deriveAes(inputKey, salt, info) {
  const baseKey = await subtle.importKey(
    "raw",
    arrayBuffer(inputKey),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: arrayBuffer(salt),
      info: arrayBuffer(info),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
}

async function makeEnvelope({
  evaluatorKeyPair,
  policyHash,
  inviteeId,
  index,
  response = "going",
  minimumParticipants = 2,
  requiredGroups = [],
}) {
  const suffix = String(index).padStart(12, "0");
  const envelopeId = `40000000-0000-4000-8000-${suffix}`;
  const accountKeyEpochId = `50000000-0000-4000-8000-${suffix}`;
  const draft = {
    protocolVersion: PROTOCOL_VERSION,
    eventId: EVENT_ID,
    inviteeId,
    policyHash,
    envelopeId,
    accountKeyEpochId,
    revision: 1,
    response,
    minimumParticipants: response === "cant_commit" ? null : minimumParticipants,
    requiredGroups: response === "cant_commit" ? [] : requiredGroups,
    nonce: base64Url(new Uint8Array(16).fill(30 + index)),
  };
  const envelope = {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    envelopeId,
    eventId: EVENT_ID,
    inviteeId,
    policyHash,
    revision: 1,
    accountKeyEpochId,
    evaluatorKeyId: KEY_ID,
    payloadCiphertext: "",
    userKeyWrap: base64Url(new Uint8Array(USER_WRAP_BYTES).fill(10 + index)),
    evaluatorKeyWrap: "",
  };

  const draftBytes = encoder.encode(JSON.stringify(draft));
  const padded = new Uint8Array(PADDED_PLAINTEXT_BYTES);
  new DataView(padded.buffer).setUint16(0, draftBytes.length, false);
  padded.set(draftBytes, 2);
  const responseKeyBytes = webcrypto.getRandomValues(new Uint8Array(32));
  const responseKey = await subtle.importKey(
    "raw",
    arrayBuffer(responseKeyBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  envelope.payloadCiphertext = base64Url(
    await sealAesFrame(
      responseKey,
      padded,
      labeled("HERD-RSVP-PAYLOAD-AAD-V1", envelope),
    ),
  );

  const ephemeralKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const ephemeralPublicKey = new Uint8Array(
    await subtle.exportKey("raw", ephemeralKeyPair.publicKey),
  );
  const sharedSecret = new Uint8Array(
    await subtle.deriveBits(
      { name: "ECDH", public: evaluatorKeyPair.publicKey },
      ephemeralKeyPair.privateKey,
      256,
    ),
  );
  const salt = webcrypto.getRandomValues(new Uint8Array(32));
  const keyIdBytes = encoder.encode(KEY_ID);
  const evaluatorKek = await deriveAes(
    sharedSecret,
    salt,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-KEK-V1", envelope),
      keyIdBytes,
    ),
  );
  const wrappedKey = await sealAesFrame(
    evaluatorKek,
    responseKeyBytes,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-WRAP-AAD-V1", envelope),
      keyIdBytes,
      ephemeralPublicKey,
      salt,
    ),
  );
  envelope.evaluatorKeyWrap = base64Url(
    concatenate(ephemeralPublicKey, salt, wrappedKey),
  );
  assert.equal(Buffer.from(envelope.payloadCiphertext, "base64url").length, PAYLOAD_FRAME_BYTES);
  assert.equal(Buffer.from(envelope.evaluatorKeyWrap, "base64url").length, EVALUATOR_WRAP_BYTES);
  await authorizeEnvelope(envelope);
  return envelope;
}

async function makeFixture({
  deadline = "2025-01-01T00:00:00.000Z",
  eventDate = "2030-01-01T00:00:00.000Z",
  minimumParticipants = 2,
  hostRequiredGroups = [],
  responseSpecs = [
    { inviteeId: INVITEE_A, response: "going" },
    { inviteeId: INVITEE_B, response: "going" },
  ],
} = {}) {
  const evaluatorKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const privateJwk = await subtle.exportKey("jwk", evaluatorKeyPair.privateKey);
  const publicKey = base64Url(
    new Uint8Array(await subtle.exportKey("raw", evaluatorKeyPair.publicKey)),
  );
  const memberIds = [INVITEE_A, INVITEE_B];
  const canonicalDocumentValue = {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    event: {
      id: EVENT_ID,
      title: "Service integration test",
      eventDate,
      endDate: null,
      hostName: "Herd Test Host",
      locationName: "",
      locationAddress: "",
      eventDescription: "",
    },
    members: memberIds.map((id) => ({ id })),
    hostRules: {
      minimumParticipants,
      requiredGroups: hostRequiredGroups,
    },
    rsvpDeadline: deadline,
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits: {
      maximumParticipants: 3,
      maximumConditionGroups: 2,
      maximumMembersPerGroup: 2,
      paddedPlaintextBytes: PADDED_PLAINTEXT_BYTES,
    },
    evaluator: {
      keyId: KEY_ID,
      publicKey,
      measurement: MEASUREMENT,
    },
    releaseId: RELEASE_ID,
  };
  const canonicalDocument = JSON.stringify(canonicalDocumentValue);
  const policyHash = await sha256(canonicalDocument);
  const policy = {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    policyHash,
    canonicalDocument,
    evaluatorKeyId: KEY_ID,
    evaluatorPublicKey: publicKey,
    evaluatorMeasurement: MEASUREMENT,
    releaseId: RELEASE_ID,
    paddedPlaintextBytes: PADDED_PLAINTEXT_BYTES,
    frozenAt: "2024-12-01T00:00:00.000Z",
  };

  const specsByMember = new Map(responseSpecs.map((spec) => [spec.inviteeId, spec]));
  const slots = [];
  for (const [index, inviteeId] of memberIds.entries()) {
    const spec = specsByMember.get(inviteeId);
    if (!spec) {
      slots.push({ inviteeId, envelopeHash: null, envelope: null });
      continue;
    }
    const envelope = await makeEnvelope({
      evaluatorKeyPair,
      policyHash,
      inviteeId,
      index: index + 1,
      ...spec,
    });
    slots.push({
      inviteeId,
      envelopeHash: await envelopeCommitmentHash(envelope),
      envelope,
    });
  }
  const request = {
    protocolVersion: PROTOCOL_VERSION,
    eventId: EVENT_ID,
    policy,
    batchHash: "",
    slots,
  };
  request.batchHash = await computeBatchHash(request);
  const bindings = {
    HERD_EVALUATOR_TOKEN: TOKEN,
    HERD_EVALUATOR_KEY_ID: KEY_ID,
    HERD_EVALUATOR_PRIVATE_KEY_PEM: sec1Pem(privateJwk),
    HERD_EVALUATOR_MEASUREMENT: MEASUREMENT,
    HERD_RELEASE_ID: RELEASE_ID,
  };
  return { request, bindings };
}

async function computeBatchHash(request) {
  return sha256(
    JSON.stringify({
      protocolVersion: PROTOCOL_VERSION,
      eventId: request.eventId,
      policyHash: request.policy.policyHash,
      slots: request.slots.map(({ inviteeId, envelopeHash }) => ({
        inviteeId,
        envelopeHash,
      })),
    }),
  );
}

function clone(value) {
  return structuredClone(value);
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

function relayCapabilityDocument(request) {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
    ciphertext: request.ciphertext,
  });
}

function normalizedRelayJson(request) {
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

async function relayCapabilityMac(request, token = TOKEN) {
  const key = await subtle.importKey(
    "raw",
    encoder.encode(token),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return base64Url(
    new Uint8Array(
      await subtle.sign(
        "HMAC",
        key,
        arrayBuffer(
          concatenate(
            encoder.encode(RELAY_CAPABILITY_LABEL),
            encoder.encode(relayCapabilityDocument(request)),
          ),
        ),
      ),
    ),
  );
}

async function makeRelayFixture({
  evaluationFixture,
  issuedAt,
  expiresAt,
  paddingByte = 0,
} = {}) {
  const fixture = evaluationFixture ?? (await makeFixture());
  const now = Date.now();
  const inner = {
    protocolVersion: PROTOCOL_VERSION,
    relayRequestId: RELAY_REQUEST_ID,
    leaseId: LEASE_ID,
    issuedAt: issuedAt ?? new Date(now - 1_000).toISOString(),
    expiresAt: expiresAt ?? new Date(now + 60_000).toISOString(),
    evaluationRequest: fixture.request,
  };
  const innerBytes = encoder.encode(JSON.stringify(inner));
  assert.ok(innerBytes.length <= 256 * 1024);
  const frame = new Uint8Array(RELAY_PLAINTEXT_BYTES);
  new DataView(frame.buffer).setUint32(0, innerBytes.length, false);
  frame.set(innerBytes, 4);
  if (paddingByte !== 0) frame[frame.length - 1] = paddingByte;

  const evaluatorPublicKey = await subtle.importKey(
    "raw",
    arrayBuffer(
      new Uint8Array(
        Buffer.from(fixture.request.policy.evaluatorPublicKey, "base64url"),
      ),
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
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    evaluatorKeyId: KEY_ID,
    ephemeralPublicKey: base64Url(ephemeralPublicKey),
    salt: base64Url(salt),
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
  const aesKey = await deriveAes(
    sharedSecret,
    salt,
    concatenate(encoder.encode(RELAY_KEY_LABEL), context),
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertextAndTag = new Uint8Array(
    await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: arrayBuffer(iv),
        additionalData: arrayBuffer(
          concatenate(encoder.encode(RELAY_AAD_LABEL), context),
        ),
        tagLength: 128,
      },
      aesKey,
      arrayBuffer(frame),
    ),
  );
  request.ciphertext = base64Url(concatenate(iv, ciphertextAndTag));
  assert.equal(
    Buffer.from(request.ciphertext, "base64url").length,
    RELAY_CIPHERTEXT_BYTES,
  );
  request.capabilityMac = await relayCapabilityMac(request);

  const signingKeyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const signingPrivateJwk = await subtle.exportKey(
    "jwk",
    signingKeyPair.privateKey,
  );
  const bindings = {
    ...fixture.bindings,
    HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: RESULT_SIGNING_KEY_ID,
    HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK:
      JSON.stringify(signingPrivateJwk),
    HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN: RELAY_ORIGIN,
  };
  return {
    request,
    inner,
    bindings,
    signingPublicKey: signingKeyPair.publicKey,
    evaluationFixture: fixture,
  };
}

async function verifyRelayAttestation(response, publicKey) {
  const signature = new Uint8Array(
    Buffer.from(response.attestation.signature, "base64url"),
  );
  assert.equal(signature.length, 64);
  return subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    arrayBuffer(signature),
    encoder.encode(response.attestation.canonicalDocument),
  );
}

async function serviceFetch({
  body,
  bindings,
  token = TOKEN,
  contentType = "application/json",
  headers = {},
  path = "/api/v1/evaluate",
  method = "POST",
}) {
  const requestHeaders = new Headers(headers);
  if (token !== null) requestHeaders.set("authorization", `Bearer ${token}`);
  if (contentType !== null) requestHeaders.set("content-type", contentType);
  const miniflare = await createHarness(bindings ?? {});
  try {
    const response = await miniflare.dispatchFetch(`https://evaluator.test${path}`, {
      method,
      headers: requestHeaders,
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
    const responseBody = await response.arrayBuffer();
    return new Response(response.status === 204 ? null : responseBody, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } finally {
    await miniflare.dispose();
  }
}

test("status page names the service without exposing operational values", async () => {
  const response = await serviceFetch({
    path: "/",
    method: "GET",
    token: null,
    contentType: null,
  });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Herd confidential evaluator/i);
  assert.match(html, /does not expose response details/i);
  assert.doesNotMatch(html, /HERD_EVALUATOR|private.*key|Bearer /i);
});

test("confirms a valid committed batch and returns only the allowed projection", async () => {
  const fixture = await makeFixture();
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.deepEqual(await response.json(), {
    protocolVersion: PROTOCOL_VERSION,
    eventId: EVENT_ID,
    policyHash: fixture.request.policy.policyHash,
    batchHash: fixture.request.batchHash,
    evaluatorKeyId: KEY_ID,
    status: "confirmed",
    attendingMemberIds: ["host", INVITEE_A, INVITEE_B],
  });
});

test("not-confirmed omits all guest-level response and condition details", async () => {
  const fixture = await makeFixture({ responseSpecs: [] });
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.deepEqual(result, {
    protocolVersion: PROTOCOL_VERSION,
    eventId: EVENT_ID,
    policyHash: fixture.request.policy.policyHash,
    batchHash: fixture.request.batchHash,
    evaluatorKeyId: KEY_ID,
    status: "not_confirmed",
  });
  assert.deepEqual(Object.keys(result), [
    "protocolVersion",
    "eventId",
    "policyHash",
    "batchHash",
    "evaluatorKeyId",
    "status",
  ]);
});

test("enforces frozen host-required people without revealing the failed rule", async () => {
  const fixture = await makeFixture({
    hostRequiredGroups: [{ id: HOST_GROUP, memberIDs: [INVITEE_B] }],
    responseSpecs: [{ inviteeId: INVITEE_A, response: "going" }],
  });
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, "not_confirmed");
});

test("applies conditional-attendance cascades at the service boundary", async () => {
  const fixture = await makeFixture({
    responseSpecs: [
      {
        inviteeId: INVITEE_A,
        response: "going",
        requiredGroups: [{ id: RESPONSE_GROUP, memberIDs: [INVITEE_B] }],
      },
      { inviteeId: INVITEE_B, response: "cant_commit" },
    ],
  });
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, "not_confirmed");
});

test("rejects unauthenticated calls before processing their body", async () => {
  const fixture = await makeFixture();
  for (const token of [null, "wrong-token-that-is-long-enough-but-still-wrong"] ) {
    const response = await serviceFetch({
      body: fixture.request,
      bindings: fixture.bindings,
      token,
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: { code: "unauthorized" } });
  }
});

test("rejects evaluation before the frozen deadline", async () => {
  const fixture = await makeFixture({
    deadline: "2099-01-01T00:00:00.000Z",
    eventDate: "2100-01-01T00:00:00.000Z",
  });
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: { code: "deadline_not_reached" } });
});

test("rejects policy, member order, and batch commitment tampering", async (context) => {
  await context.test("canonical policy text", async () => {
    const fixture = await makeFixture();
    const request = clone(fixture.request);
    request.policy.canonicalDocument = request.policy.canonicalDocument.replace(
      "Service integration test",
      "Tampered event",
    );
    const response = await serviceFetch({ body: request, bindings: fixture.bindings });
    assert.equal(response.status, 400);
  });

  await context.test("member PII is not a valid canonical policy field", async () => {
    const fixture = await makeFixture();
    const request = clone(fixture.request);
    const document = JSON.parse(request.policy.canonicalDocument);
    document.members[0].displayName = "Must not be retained";
    document.members[0].phoneAssignment = base64Url(
      new Uint8Array(32).fill(7),
    );
    request.policy.canonicalDocument = JSON.stringify(document);
    request.policy.policyHash = await sha256(request.policy.canonicalDocument);
    const response = await serviceFetch({
      body: request,
      bindings: fixture.bindings,
    });
    assert.equal(response.status, 400);
  });

  await context.test("slot order", async () => {
    const fixture = await makeFixture();
    const request = clone(fixture.request);
    request.slots.reverse();
    request.batchHash = await computeBatchHash(request);
    const response = await serviceFetch({ body: request, bindings: fixture.bindings });
    assert.equal(response.status, 400);
  });

  await context.test("batch hash", async () => {
    const fixture = await makeFixture();
    const request = clone(fixture.request);
    request.batchHash = base64Url(new Uint8Array(32).fill(99));
    const response = await serviceFetch({ body: request, bindings: fixture.bindings });
    assert.equal(response.status, 400);
  });

  await context.test("duplicate envelope ID", async () => {
    const fixture = await makeFixture();
    const request = clone(fixture.request);
    request.slots[1].envelope.envelopeId = request.slots[0].envelope.envelopeId;
    request.slots[1].envelopeHash = await authorizeEnvelope(
      request.slots[1].envelope,
    );
    request.batchHash = await computeBatchHash(request);
    const response = await serviceFetch({ body: request, bindings: fixture.bindings });
    assert.equal(response.status, 400);
  });

  await context.test("response authorization signature", async () => {
    const fixture = await makeFixture();
    const request = clone(fixture.request);
    const signature = new Uint8Array(
      Buffer.from(request.slots[0].envelope.responseSignature, "base64url"),
    );
    signature[0] ^= 1;
    request.slots[0].envelope.responseSignature = base64Url(signature);
    const response = await serviceFetch({
      body: request,
      bindings: fixture.bindings,
    });
    assert.equal(response.status, 400);
  });
});

test("isolates authenticated ciphertext tampering as a privacy-safe nonresponse", async () => {
  const fixture = await makeFixture();
  const request = clone(fixture.request);
  const ciphertext = new Uint8Array(
    Buffer.from(request.slots[0].envelope.payloadCiphertext, "base64url"),
  );
  ciphertext[ciphertext.length - 1] ^= 1;
  request.slots[0].envelope.payloadCiphertext = base64Url(ciphertext);
  request.slots[0].envelopeHash = await authorizeEnvelope(
    request.slots[0].envelope,
  );
  request.batchHash = await computeBatchHash(request);
  const response = await serviceFetch({ body: request, bindings: fixture.bindings });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    protocolVersion: PROTOCOL_VERSION,
    eventId: EVENT_ID,
    policyHash: request.policy.policyHash,
    batchHash: request.batchHash,
    evaluatorKeyId: KEY_ID,
    status: "confirmed",
    attendingMemberIds: ["host", INVITEE_B],
  });
});

test("all undecryptable envelopes resolve without exposing failure details", async () => {
  const fixture = await makeFixture();
  const request = clone(fixture.request);
  for (const slot of request.slots) {
    const ciphertext = new Uint8Array(
      Buffer.from(slot.envelope.payloadCiphertext, "base64url"),
    );
    ciphertext[ciphertext.length - 1] ^= 1;
    slot.envelope.payloadCiphertext = base64Url(ciphertext);
    slot.envelopeHash = await authorizeEnvelope(slot.envelope);
  }
  request.batchHash = await computeBatchHash(request);

  const response = await serviceFetch({ body: request, bindings: fixture.bindings });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.deepEqual(result, {
    protocolVersion: PROTOCOL_VERSION,
    eventId: EVENT_ID,
    policyHash: request.policy.policyHash,
    batchHash: request.batchHash,
    evaluatorKeyId: KEY_ID,
    status: "not_confirmed",
  });
  assert.deepEqual(Object.keys(result), [
    "protocolVersion",
    "eventId",
    "policyHash",
    "batchHash",
    "evaluatorKeyId",
    "status",
  ]);
});

test("rejects a policy public key that does not match the isolated private key", async () => {
  const fixture = await makeFixture();
  const otherKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  fixture.bindings.HERD_EVALUATOR_PRIVATE_KEY_PEM = sec1Pem(
    await subtle.exportKey("jwk", otherKeyPair.privateKey),
  );
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 400);
});

test("uses generic bounded HTTP errors for malformed and oversized requests", async (context) => {
  const fixture = await makeFixture();
  await context.test("wrong media type", async () => {
    const response = await serviceFetch({
      body: fixture.request,
      bindings: fixture.bindings,
      contentType: "text/plain",
    });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: { code: "invalid_request" } });
  });

  await context.test("unsupported field", async () => {
    const response = await serviceFetch({
      body: { ...fixture.request, debug: true },
      bindings: fixture.bindings,
    });
    assert.equal(response.status, 400);
  });

  await context.test("oversized body", async () => {
    const response = await serviceFetch({
      body: JSON.stringify({ padding: "x".repeat(256 * 1024) }),
      bindings: fixture.bindings,
    });
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), { error: { code: "request_too_large" } });
  });
});

test("fails closed when evaluator secrets are incomplete", async () => {
  const fixture = await makeFixture();
  delete fixture.bindings.HERD_EVALUATOR_PRIVATE_KEY_PEM;
  const response = await serviceFetch({ body: fixture.request, bindings: fixture.bindings });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: { code: "service_unavailable" } });
});

test("relay evaluates a fixed-size opaque request and returns a verifiable bound attestation", async () => {
  const fixture = await makeRelayFixture();
  const response = await serviceFetch({
    path: "/api/v1/relay",
    body: fixture.request,
    bindings: fixture.bindings,
    token: null,
    headers: { origin: RELAY_ORIGIN },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("access-control-allow-origin"), RELAY_ORIGIN);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(
    Buffer.from(fixture.request.ciphertext, "base64url").length,
    RELAY_CIPHERTEXT_BYTES,
  );
  const body = await response.json();
  const expectedRequestHash = await sha256(normalizedRelayJson(fixture.request));
  assert.deepEqual(Object.keys(body), [
    "protocolVersion",
    "relayRequestHash",
    "relayRequestId",
    "leaseId",
    "result",
    "attestation",
  ]);
  assert.equal(body.protocolVersion, PROTOCOL_VERSION);
  assert.equal(body.relayRequestHash, expectedRequestHash);
  assert.equal(body.relayRequestId, RELAY_REQUEST_ID);
  assert.equal(body.leaseId, LEASE_ID);
  assert.equal(body.result.status, "confirmed");
  assert.deepEqual(body.result.attendingMemberIds, [
    "host",
    INVITEE_A,
    INVITEE_B,
  ]);
  assert.deepEqual(Object.keys(body.attestation), [
    "protocolVersion",
    "signingKeyId",
    "evaluatedAt",
    "canonicalDocument",
    "signature",
  ]);
  const expectedCanonicalDocument = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    signingKeyId: RESULT_SIGNING_KEY_ID,
    relayRequestHash: expectedRequestHash,
    relayRequestId: RELAY_REQUEST_ID,
    leaseId: LEASE_ID,
    evaluatedAt: body.attestation.evaluatedAt,
    result: body.result,
  });
  assert.equal(body.attestation.canonicalDocument, expectedCanonicalDocument);
  assert.equal(await verifyRelayAttestation(body, fixture.signingPublicKey), true);

  const wrongKeyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  assert.equal(await verifyRelayAttestation(body, wrongKeyPair.publicKey), false);
  const originalSignature = new Uint8Array(
    Buffer.from(body.attestation.signature, "base64url"),
  );
  for (const mutate of [
    (document) => {
      document.relayRequestHash = base64Url(new Uint8Array(32).fill(88));
    },
    (document) => {
      document.leaseId = "70000000-0000-4000-8000-000000000002";
    },
    (document) => {
      document.result = { ...document.result, status: "not_confirmed" };
      delete document.result.attendingMemberIds;
    },
  ]) {
    const document = JSON.parse(body.attestation.canonicalDocument);
    mutate(document);
    assert.equal(
      await subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        fixture.signingPublicKey,
        arrayBuffer(originalSignature),
        encoder.encode(JSON.stringify(document)),
      ),
      false,
    );
  }
  const tamperedSignature = new Uint8Array(
    Buffer.from(body.attestation.signature, "base64url"),
  );
  tamperedSignature[0] ^= 1;
  body.attestation.signature = base64Url(tamperedSignature);
  assert.equal(await verifyRelayAttestation(body, fixture.signingPublicKey), false);
});

test("relay transport accepts reordered keys and insignificant JSON whitespace", async () => {
  const fixture = await makeRelayFixture();
  const reordered = {
    capabilityMac: fixture.request.capabilityMac,
    ciphertext: fixture.request.ciphertext,
    salt: fixture.request.salt,
    ephemeralPublicKey: fixture.request.ephemeralPublicKey,
    evaluatorKeyId: fixture.request.evaluatorKeyId,
    cipherSuite: fixture.request.cipherSuite,
    protocolVersion: fixture.request.protocolVersion,
  };
  const response = await serviceFetch({
    path: "/api/v1/relay",
    body: JSON.stringify(reordered, null, 2),
    bindings: fixture.bindings,
    token: null,
    headers: { origin: RELAY_ORIGIN },
  });
  assert.equal(response.status, 200);
  assert.equal(
    (await response.json()).relayRequestHash,
    await sha256(normalizedRelayJson(fixture.request)),
  );
});

test("relay rejects capability, ciphertext, frame, size, and schema tampering", async (context) => {
  const fixture = await makeRelayFixture();

  await context.test("capability MAC", async () => {
    const request = clone(fixture.request);
    const mac = new Uint8Array(Buffer.from(request.capabilityMac, "base64url"));
    mac[0] ^= 1;
    request.capabilityMac = base64Url(mac);
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: { code: "unauthorized" } });
  });

  await context.test("ciphertext without a new capability", async () => {
    const request = clone(fixture.request);
    const ciphertext = new Uint8Array(
      Buffer.from(request.ciphertext, "base64url"),
    );
    ciphertext[ciphertext.length - 1] ^= 1;
    request.ciphertext = base64Url(ciphertext);
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 401);
  });

  await context.test("authenticated ciphertext corruption", async () => {
    const request = clone(fixture.request);
    const ciphertext = new Uint8Array(
      Buffer.from(request.ciphertext, "base64url"),
    );
    ciphertext[ciphertext.length - 1] ^= 1;
    request.ciphertext = base64Url(ciphertext);
    request.capabilityMac = await relayCapabilityMac(request);
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: { code: "invalid_request" } });
  });

  await context.test("non-zero plaintext padding", async () => {
    const padded = await makeRelayFixture({ paddingByte: 1 });
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: padded.request,
      bindings: padded.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 400);
  });

  await context.test("non-fixed ciphertext size", async () => {
    const request = clone(fixture.request);
    const ciphertext = new Uint8Array(
      Buffer.from(request.ciphertext, "base64url"),
    );
    request.ciphertext = base64Url(ciphertext.subarray(0, ciphertext.length - 1));
    request.capabilityMac = await relayCapabilityMac(request);
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 400);
  });

  await context.test("unsupported outer field", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: { ...fixture.request, debug: true },
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 400);
  });

  await context.test("oversized transport body", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: JSON.stringify({ padding: "x".repeat(437_391) }),
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), {
      error: { code: "request_too_large" },
    });
  });

  await context.test("wrong media type", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings: fixture.bindings,
      token: null,
      contentType: "text/plain",
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 400);
  });
});

test("relay enforces short-lived capabilities and strict browser origins", async (context) => {
  const now = Date.now();
  await context.test("expired", async () => {
    const fixture = await makeRelayFixture({
      issuedAt: new Date(now - 120_000).toISOString(),
      expiresAt: new Date(now - 1_000).toISOString(),
    });
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 401);
  });

  await context.test("lifetime over two minutes", async () => {
    const fixture = await makeRelayFixture({
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_001).toISOString(),
    });
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 401);
  });

  await context.test("issued too far in the future", async () => {
    const fixture = await makeRelayFixture({
      issuedAt: new Date(now + 60_000).toISOString(),
      expiresAt: new Date(now + 90_000).toISOString(),
    });
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 401);
  });

  await context.test("wrong browser origin", async () => {
    const fixture = await makeRelayFixture();
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings: fixture.bindings,
      token: null,
      headers: { origin: "https://attacker.test" },
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
  });

  await context.test("native request without Origin", async () => {
    const fixture = await makeRelayFixture();
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings: fixture.bindings,
      token: null,
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
  });
});

test("relay CORS preflight is exact and signing configuration fails closed", async (context) => {
  const fixture = await makeRelayFixture();
  await context.test("valid preflight", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      method: "OPTIONS",
      body: undefined,
      bindings: fixture.bindings,
      token: null,
      contentType: null,
      headers: {
        origin: RELAY_ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), RELAY_ORIGIN);
    assert.equal(response.headers.get("access-control-allow-methods"), "POST");
    assert.equal(
      response.headers.get("access-control-allow-headers"),
      "content-type, cache-control, pragma",
    );
  });

  await context.test("browser no-store preflight headers", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      method: "OPTIONS",
      bindings: fixture.bindings,
      token: null,
      contentType: null,
      headers: {
        origin: RELAY_ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers":
          "Pragma, Content-Type, Cache-Control",
      },
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), RELAY_ORIGIN);
  });

  await context.test("wrong preflight origin", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      method: "OPTIONS",
      bindings: fixture.bindings,
      token: null,
      contentType: null,
      headers: {
        origin: "https://attacker.test",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
  });

  await context.test("unapproved preflight header", async () => {
    const response = await serviceFetch({
      path: "/api/v1/relay",
      method: "OPTIONS",
      bindings: fixture.bindings,
      token: null,
      contentType: null,
      headers: {
        origin: RELAY_ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization, content-type",
      },
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("access-control-allow-origin"), RELAY_ORIGIN);
  });

  await context.test("missing result-signing secret", async () => {
    const bindings = { ...fixture.bindings };
    delete bindings.HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK;
    const response = await serviceFetch({
      path: "/api/v1/relay",
      body: fixture.request,
      bindings,
      token: null,
      headers: { origin: RELAY_ORIGIN },
    });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      error: { code: "service_unavailable" },
    });
  });
});
