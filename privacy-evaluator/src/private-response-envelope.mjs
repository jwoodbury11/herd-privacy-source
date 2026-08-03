import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const VERSION = 1;
const CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM";
const PADDED_PLAINTEXT_BYTES = 4_096;
const PAYLOAD_FRAME_BYTES = 4_124;
const USER_WRAP_BYTES = 60;
const EVALUATOR_WRAP_BYTES = 157;
const EVALUATOR_PUBLIC_KEY_BYTES = 65;
const EVALUATOR_SALT_BYTES = 32;
const NONCE_BYTES = 12;
const RESPONSE_KEY_BYTES = 32;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

const ENVELOPE_KEYS = [
  "protocolVersion",
  "cipherSuite",
  "envelopeId",
  "eventId",
  "inviteeId",
  "policyHash",
  "revision",
  "accountKeyEpochId",
  "evaluatorKeyId",
  "payloadCiphertext",
  "userKeyWrap",
  "evaluatorKeyWrap",
  "responseSigningPublicKey",
  "responseSignature",
];

const DRAFT_KEYS = [
  "protocolVersion",
  "eventId",
  "inviteeId",
  "policyHash",
  "envelopeId",
  "accountKeyEpochId",
  "revision",
  "response",
  "minimumParticipants",
  "requiredGroups",
  "nonce",
];

function record(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}

function exactKeys(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError(`${field} contains unsupported fields.`);
  }
}

function uuid(value, field) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError(`${field} must be a lowercase UUID.`);
  }
  return value;
}

function integer(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}

function decodeBase64Url(value, field, expectedBytes) {
  if (
    typeof value !== "string" ||
    !value ||
    !BASE64URL_PATTERN.test(value) ||
    value.length % 4 === 1
  ) {
    throw new TypeError(`${field} is not canonical base64url.`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.length !== expectedBytes ||
    decoded.toString("base64url") !== value
  ) {
    throw new TypeError(`${field} must encode exactly ${expectedBytes} bytes.`);
  }
  return new Uint8Array(decoded);
}

function uuidBytes(value, field) {
  return new Uint8Array(Buffer.from(uuid(value, field).replaceAll("-", ""), "hex"));
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

function normalizeEnvelope(value) {
  const input = record(value, "envelope");
  exactKeys(input, ENVELOPE_KEYS, "envelope");
  if (input.protocolVersion !== VERSION || input.cipherSuite !== CIPHER_SUITE) {
    throw new TypeError("envelope uses an unsupported protocol or cipher suite.");
  }
  if (
    typeof input.evaluatorKeyId !== "string" ||
    !/^[A-Za-z0-9._-]{1,120}$/.test(input.evaluatorKeyId)
  ) {
    throw new TypeError("envelope.evaluatorKeyId is invalid.");
  }
  return {
    protocolVersion: VERSION,
    cipherSuite: CIPHER_SUITE,
    envelopeId: uuid(input.envelopeId, "envelope.envelopeId"),
    eventId: uuid(input.eventId, "envelope.eventId"),
    inviteeId: uuid(input.inviteeId, "envelope.inviteeId"),
    policyHash: Buffer.from(
      decodeBase64Url(input.policyHash, "envelope.policyHash", 32),
    ).toString("base64url"),
    revision: integer(input.revision, "envelope.revision", 1, 1_000_000),
    accountKeyEpochId: uuid(
      input.accountKeyEpochId,
      "envelope.accountKeyEpochId",
    ),
    evaluatorKeyId: input.evaluatorKeyId,
    payloadCiphertext: Buffer.from(
      decodeBase64Url(
        input.payloadCiphertext,
        "envelope.payloadCiphertext",
        PAYLOAD_FRAME_BYTES,
      ),
    ).toString("base64url"),
    userKeyWrap: Buffer.from(
      decodeBase64Url(input.userKeyWrap, "envelope.userKeyWrap", USER_WRAP_BYTES),
    ).toString("base64url"),
    evaluatorKeyWrap: Buffer.from(
      decodeBase64Url(
        input.evaluatorKeyWrap,
        "envelope.evaluatorKeyWrap",
        EVALUATOR_WRAP_BYTES,
      ),
    ).toString("base64url"),
    responseSigningPublicKey: Buffer.from(
      decodeBase64Url(
        input.responseSigningPublicKey,
        "envelope.responseSigningPublicKey",
        32,
      ),
    ).toString("base64url"),
    responseSignature: Buffer.from(
      decodeBase64Url(
        input.responseSignature,
        "envelope.responseSignature",
        64,
      ),
    ).toString("base64url"),
  };
}

function context(envelope) {
  const result = new Uint8Array(101);
  let offset = 0;
  result[offset] = VERSION;
  offset += 1;
  for (const value of [
    uuidBytes(envelope.eventId, "eventId"),
    uuidBytes(envelope.inviteeId, "inviteeId"),
    decodeBase64Url(envelope.policyHash, "policyHash", 32),
    uuidBytes(envelope.envelopeId, "envelopeId"),
    uuidBytes(envelope.accountKeyEpochId, "accountKeyEpochId"),
  ]) {
    result.set(value, offset);
    offset += value.length;
  }
  new DataView(result.buffer).setUint32(offset, envelope.revision, false);
  return result;
}

function labeled(label, envelope) {
  return concatenate(encoder.encode(label), new Uint8Array([0]), context(envelope));
}

async function deriveAesKey(inputKey, salt, info, usages) {
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
    usages,
  );
}

async function openAesFrame(key, frame, aad, expectedPlaintextBytes) {
  if (frame.length !== NONCE_BYTES + expectedPlaintextBytes + 16) {
    throw new TypeError("encrypted frame has the wrong size.");
  }
  try {
    return new Uint8Array(
      await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: arrayBuffer(frame.subarray(0, NONCE_BYTES)),
          additionalData: arrayBuffer(aad),
          tagLength: 128,
        },
        key,
        arrayBuffer(frame.subarray(NONCE_BYTES)),
      ),
    );
  } catch {
    throw new TypeError("encrypted frame authentication failed.");
  }
}

function normalizeParticipantPolicy(allowedInviteeIds, hostMinimumParticipants) {
  if (!Array.isArray(allowedInviteeIds)) {
    throw new TypeError("allowedInviteeIds is invalid.");
  }
  const allowed = new Set(
    allowedInviteeIds.map((value, index) =>
      uuid(value, `allowedInviteeIds[${index}]`),
    ),
  );
  if (allowed.size !== allowedInviteeIds.length || allowed.size > 19) {
    throw new TypeError("allowedInviteeIds is invalid.");
  }
  const maximumParticipants = allowed.size + 1;
  return {
    allowed,
    maximumParticipants,
    hostMinimumParticipants: integer(
      hostMinimumParticipants,
      "hostMinimumParticipants",
      2,
      maximumParticipants,
    ),
  };
}

function normalizeDraft(value, envelope, participantPolicy) {
  const input = record(value, "private response");
  exactKeys(input, DRAFT_KEYS, "private response");
  const { allowed, hostMinimumParticipants, maximumParticipants } = participantPolicy;
  if (input.protocolVersion !== VERSION) {
    throw new TypeError("private response version is unsupported.");
  }
  const response = input.response;
  if (response !== "going" && response !== "cant_commit") {
    throw new TypeError("private response value is invalid.");
  }
  const minimumParticipants = response === "going"
    ? integer(
        input.minimumParticipants,
        "minimumParticipants",
        hostMinimumParticipants,
        maximumParticipants,
      )
    : input.minimumParticipants;
  if (response === "cant_commit" && minimumParticipants !== null) {
    throw new TypeError("cant_commit must use a null minimum.");
  }
  if (!Array.isArray(input.requiredGroups) || input.requiredGroups.length > allowed.size) {
    throw new TypeError("requiredGroups is invalid.");
  }
  const inviteeId = uuid(input.inviteeId, "inviteeId");
  if (!allowed.has(inviteeId)) {
    throw new TypeError("the respondent is not in the frozen event.");
  }
  const seenGroups = new Set();
  const seenMembers = new Set();
  const requiredGroups = input.requiredGroups.map((rawGroup, groupIndex) => {
    const group = record(rawGroup, `requiredGroups[${groupIndex}]`);
    exactKeys(group, ["id", "memberIDs"], `requiredGroups[${groupIndex}]`);
    const id = uuid(group.id, `requiredGroups[${groupIndex}].id`);
    if (seenGroups.has(id)) throw new TypeError("condition group IDs must be unique.");
    seenGroups.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      throw new TypeError("condition groups cannot be empty.");
    }
    const memberIDs = group.memberIDs.map((rawMember, memberIndex) => {
      const member = uuid(
        rawMember,
        `requiredGroups[${groupIndex}].memberIDs[${memberIndex}]`,
      );
      if (member === inviteeId || !allowed.has(member) || seenMembers.has(member)) {
        throw new TypeError("condition member is invalid or repeated.");
      }
      seenMembers.add(member);
      return member;
    });
    return { id, memberIDs };
  });
  if (response === "cant_commit" && requiredGroups.length !== 0) {
    throw new TypeError("cant_commit cannot include conditions.");
  }
  const draft = {
    protocolVersion: VERSION,
    eventId: uuid(input.eventId, "eventId"),
    inviteeId,
    policyHash: Buffer.from(
      decodeBase64Url(input.policyHash, "policyHash", 32),
    ).toString("base64url"),
    envelopeId: uuid(input.envelopeId, "envelopeId"),
    accountKeyEpochId: uuid(input.accountKeyEpochId, "accountKeyEpochId"),
    revision: integer(input.revision, "revision", 1, 1_000_000),
    response,
    minimumParticipants,
    requiredGroups,
    nonce: Buffer.from(decodeBase64Url(input.nonce, "nonce", 16)).toString("base64url"),
  };
  for (const field of [
    "protocolVersion",
    "eventId",
    "inviteeId",
    "policyHash",
    "envelopeId",
    "accountKeyEpochId",
    "revision",
  ]) {
    if (draft[field] !== envelope[field]) {
      throw new TypeError(`private response ${field} does not match its envelope.`);
    }
  }
  return draft;
}

function validateEvaluatorPrivateKey(key) {
  if (
    !key ||
    key.type !== "private" ||
    key.algorithm?.name !== "ECDH" ||
    key.algorithm?.namedCurve !== "P-256" ||
    !key.usages.includes("deriveBits")
  ) {
    throw new TypeError("evaluatorPrivateKey must be a P-256 ECDH private CryptoKey.");
  }
}

/**
 * Decrypt one v1 envelope at the confidential-evaluator boundary.
 *
 * Callers must verify the frozen policy, evaluator key ID, batch commitment,
 * deadline authorization, and enclave attestation before invoking this method.
 * hostMinimumParticipants must come from that validated frozen policy.
 */
export async function openPrivateResponseEnvelope({
  envelope: envelopeInput,
  evaluatorPrivateKey,
  expectedEvaluatorKeyId,
  allowedInviteeIds,
  hostMinimumParticipants,
}) {
  const envelope = normalizeEnvelope(envelopeInput);
  validateEvaluatorPrivateKey(evaluatorPrivateKey);
  if (envelope.evaluatorKeyId !== expectedEvaluatorKeyId) {
    throw new TypeError("envelope uses the wrong evaluator key ID.");
  }
  const participantPolicy = normalizeParticipantPolicy(
    allowedInviteeIds,
    hostMinimumParticipants,
  );

  const evaluatorWrap = decodeBase64Url(
    envelope.evaluatorKeyWrap,
    "evaluatorKeyWrap",
    EVALUATOR_WRAP_BYTES,
  );
  const ephemeralPublicKeyBytes = evaluatorWrap.subarray(
    0,
    EVALUATOR_PUBLIC_KEY_BYTES,
  );
  if (ephemeralPublicKeyBytes[0] !== 0x04) {
    throw new TypeError("evaluator wrap contains an invalid P-256 public key.");
  }
  const salt = evaluatorWrap.subarray(
    EVALUATOR_PUBLIC_KEY_BYTES,
    EVALUATOR_PUBLIC_KEY_BYTES + EVALUATOR_SALT_BYTES,
  );
  const wrappedResponseKey = evaluatorWrap.subarray(
    EVALUATOR_PUBLIC_KEY_BYTES + EVALUATOR_SALT_BYTES,
  );
  const ephemeralPublicKey = await subtle.importKey(
    "raw",
    arrayBuffer(ephemeralPublicKeyBytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = new Uint8Array(
    await subtle.deriveBits(
      { name: "ECDH", public: ephemeralPublicKey },
      evaluatorPrivateKey,
      256,
    ),
  );
  const keyIdBytes = encoder.encode(envelope.evaluatorKeyId);
  const evaluatorKek = await deriveAesKey(
    sharedSecret,
    salt,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-KEK-V1", envelope),
      keyIdBytes,
    ),
    ["decrypt"],
  );
  sharedSecret.fill(0);
  const responseKeyBytes = await openAesFrame(
    evaluatorKek,
    wrappedResponseKey,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-WRAP-AAD-V1", envelope),
      keyIdBytes,
      ephemeralPublicKeyBytes,
      salt,
    ),
    RESPONSE_KEY_BYTES,
  );
  const responseKey = await subtle.importKey(
    "raw",
    arrayBuffer(responseKeyBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  responseKeyBytes.fill(0);
  const plaintext = await openAesFrame(
    responseKey,
    decodeBase64Url(
      envelope.payloadCiphertext,
      "payloadCiphertext",
      PAYLOAD_FRAME_BYTES,
    ),
    labeled("HERD-RSVP-PAYLOAD-AAD-V1", envelope),
    PADDED_PLAINTEXT_BYTES,
  );
  const jsonLength = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength,
  ).getUint16(0, false);
  if (jsonLength < 2 || jsonLength > PADDED_PLAINTEXT_BYTES - 2) {
    plaintext.fill(0);
    throw new TypeError("private response frame has an invalid JSON length.");
  }
  let json;
  let parsed;
  try {
    json = decoder.decode(plaintext.subarray(2, 2 + jsonLength));
    parsed = JSON.parse(json);
  } catch {
    plaintext.fill(0);
    throw new TypeError("private response JSON is invalid.");
  }
  plaintext.fill(0);
  const draft = normalizeDraft(parsed, envelope, participantPolicy);
  if (JSON.stringify(draft) !== json) {
    throw new TypeError("private response JSON is not canonical.");
  }
  return draft;
}

export const privateResponseEnvelopeConstants = Object.freeze({
  version: VERSION,
  cipherSuite: CIPHER_SUITE,
  paddedPlaintextBytes: PADDED_PLAINTEXT_BYTES,
  payloadFrameBytes: PAYLOAD_FRAME_BYTES,
  userWrapBytes: USER_WRAP_BYTES,
  evaluatorWrapBytes: EVALUATOR_WRAP_BYTES,
});
