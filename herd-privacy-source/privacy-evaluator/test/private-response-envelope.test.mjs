import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  openPrivateResponseEnvelope,
  privateResponseEnvelopeConstants,
} from "../src/private-response-envelope.mjs";

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const EVENT_ID = "10000000-0000-4000-8000-000000000001";
const INVITEE_ID = "20000000-0000-4000-8000-000000000001";
const OTHER_INVITEE_ID = "20000000-0000-4000-8000-000000000002";
const ENVELOPE_ID = "40000000-0000-4000-8000-000000000001";
const EPOCH_ID = "50000000-0000-4000-8000-000000000001";
const GROUP_ID = "60000000-0000-4000-8000-000000000001";
const EVALUATOR_KEY_ID = "herd-evaluator-test-v1";

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

function uuidBytes(value) {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}

function context(envelope) {
  const value = new Uint8Array(101);
  let offset = 0;
  value[offset] = 1;
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
  return concatenate(encoder.encode(label), new Uint8Array([0]), context(envelope));
}

async function aesSeal(key, plaintext, aad, fill) {
  const iv = new Uint8Array(12).fill(fill);
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

async function makeEnvelope(draftOverrides = {}) {
  const evaluatorKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const policyHash = Buffer.alloc(32, 7).toString("base64url");
  const draft = {
    protocolVersion: 1,
    eventId: EVENT_ID,
    inviteeId: INVITEE_ID,
    policyHash,
    envelopeId: ENVELOPE_ID,
    accountKeyEpochId: EPOCH_ID,
    revision: 1,
    response: "going",
    minimumParticipants: 2,
    requiredGroups: [{ id: GROUP_ID, memberIDs: [OTHER_INVITEE_ID] }],
    nonce: Buffer.alloc(16, 9).toString("base64url"),
    ...draftOverrides,
  };
  const envelope = {
    protocolVersion: privateResponseEnvelopeConstants.version,
    cipherSuite: privateResponseEnvelopeConstants.cipherSuite,
    envelopeId: ENVELOPE_ID,
    eventId: EVENT_ID,
    inviteeId: INVITEE_ID,
    policyHash,
    revision: 1,
    accountKeyEpochId: EPOCH_ID,
    evaluatorKeyId: EVALUATOR_KEY_ID,
    payloadCiphertext: "",
    userKeyWrap: Buffer.alloc(60, 3).toString("base64url"),
    evaluatorKeyWrap: "",
    responseSigningPublicKey: Buffer.alloc(32, 4).toString("base64url"),
    responseSignature: Buffer.alloc(64, 5).toString("base64url"),
  };
  const draftBytes = encoder.encode(JSON.stringify(draft));
  const framed = new Uint8Array(privateResponseEnvelopeConstants.paddedPlaintextBytes);
  new DataView(framed.buffer).setUint16(0, draftBytes.length, false);
  framed.set(draftBytes, 2);
  const responseKeyBytes = new Uint8Array(32).fill(11);
  const responseKey = await subtle.importKey(
    "raw",
    arrayBuffer(responseKeyBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  envelope.payloadCiphertext = Buffer.from(
    await aesSeal(
      responseKey,
      framed,
      labeled("HERD-RSVP-PAYLOAD-AAD-V1", envelope),
      12,
    ),
  ).toString("base64url");

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
  const salt = new Uint8Array(32).fill(13);
  const keyIdBytes = encoder.encode(EVALUATOR_KEY_ID);
  const evaluatorKek = await deriveAes(
    sharedSecret,
    salt,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-KEK-V1", envelope),
      keyIdBytes,
    ),
  );
  const wrappedKey = await aesSeal(
    evaluatorKek,
    responseKeyBytes,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-WRAP-AAD-V1", envelope),
      keyIdBytes,
      ephemeralPublicKey,
      salt,
    ),
    14,
  );
  envelope.evaluatorKeyWrap = Buffer.from(
    concatenate(ephemeralPublicKey, salt, wrappedKey),
  ).toString("base64url");
  return { draft, envelope, evaluatorKeyPair };
}

test("confidential evaluator opens a valid fixed-size v1 envelope", async () => {
  const fixture = await makeEnvelope();
  assert.deepEqual(
    await openPrivateResponseEnvelope({
      envelope: fixture.envelope,
      evaluatorPrivateKey: fixture.evaluatorKeyPair.privateKey,
      expectedEvaluatorKeyId: EVALUATOR_KEY_ID,
      allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
      hostMinimumParticipants: 2,
    }),
    fixture.draft,
  );
  assert.equal(
    Buffer.from(fixture.envelope.payloadCiphertext, "base64url").length,
    privateResponseEnvelopeConstants.payloadFrameBytes,
  );
  assert.equal(
    Buffer.from(fixture.envelope.evaluatorKeyWrap, "base64url").length,
    privateResponseEnvelopeConstants.evaluatorWrapBytes,
  );
});

test("tampering with the sealed payload fails authentication", async () => {
  const fixture = await makeEnvelope();
  const tampered = new Uint8Array(
    Buffer.from(fixture.envelope.payloadCiphertext, "base64url"),
  );
  tampered[tampered.length - 1] ^= 1;
  await assert.rejects(
    openPrivateResponseEnvelope({
      envelope: {
        ...fixture.envelope,
        payloadCiphertext: Buffer.from(tampered).toString("base64url"),
      },
      evaluatorPrivateKey: fixture.evaluatorKeyPair.privateKey,
      expectedEvaluatorKeyId: EVALUATOR_KEY_ID,
      allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
      hostMinimumParticipants: 2,
    }),
    /authentication failed/,
  );
});

test("the evaluator rejects extra envelope fields and the wrong key ID", async () => {
  const fixture = await makeEnvelope();
  await assert.rejects(
    openPrivateResponseEnvelope({
      envelope: { ...fixture.envelope, response: "going" },
      evaluatorPrivateKey: fixture.evaluatorKeyPair.privateKey,
      expectedEvaluatorKeyId: EVALUATOR_KEY_ID,
      allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
      hostMinimumParticipants: 2,
    }),
    /unsupported fields/,
  );
  await assert.rejects(
    openPrivateResponseEnvelope({
      envelope: fixture.envelope,
      evaluatorPrivateKey: fixture.evaluatorKeyPair.privateKey,
      expectedEvaluatorKeyId: "another-key",
      allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
      hostMinimumParticipants: 2,
    }),
    /wrong evaluator key ID/,
  );
});

test("the evaluator enforces the frozen host minimum and participant maximum", async () => {
  const belowHostMinimum = await makeEnvelope({ minimumParticipants: 2 });
  await assert.rejects(
    openPrivateResponseEnvelope({
      envelope: belowHostMinimum.envelope,
      evaluatorPrivateKey: belowHostMinimum.evaluatorKeyPair.privateKey,
      expectedEvaluatorKeyId: EVALUATOR_KEY_ID,
      allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
      hostMinimumParticipants: 3,
    }),
    /minimumParticipants is invalid/u,
  );

  const aboveParticipantMaximum = await makeEnvelope({ minimumParticipants: 4 });
  await assert.rejects(
    openPrivateResponseEnvelope({
      envelope: aboveParticipantMaximum.envelope,
      evaluatorPrivateKey: aboveParticipantMaximum.evaluatorKeyPair.privateKey,
      expectedEvaluatorKeyId: EVALUATOR_KEY_ID,
      allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
      hostMinimumParticipants: 2,
    }),
    /minimumParticipants is invalid/u,
  );
});

test("the evaluator requires a validated production host minimum", async () => {
  const fixture = await makeEnvelope();
  for (const invalidMinimum of [undefined, null, 1, 4, 2.5]) {
    await assert.rejects(
      openPrivateResponseEnvelope({
        envelope: fixture.envelope,
        evaluatorPrivateKey: fixture.evaluatorKeyPair.privateKey,
        expectedEvaluatorKeyId: EVALUATOR_KEY_ID,
        allowedInviteeIds: [INVITEE_ID, OTHER_INVITEE_ID],
        hostMinimumParticipants: invalidMinimum,
      }),
      /hostMinimumParticipants is invalid/u,
    );
  }
});
