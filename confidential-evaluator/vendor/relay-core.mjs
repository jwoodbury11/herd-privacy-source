// Generated from evaluator-service/lib/relay.ts with reviewed dependency injection; do not edit by hand.

// ../evaluator-service/vendor/privacy-evaluator/fixed-point.mjs
function requireIdentifier(value, field) {
  if (typeof value !== "string" || !value || value.length > 160) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}
function requireInteger(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return value;
}
function normalizeGroups(value, field, allowedMembers, excludedMember = null) {
  if (!Array.isArray(value) || value.length > allowedMembers.size) {
    throw new TypeError(`${field} is invalid.`);
  }
  const seenMembers = /* @__PURE__ */ new Set();
  const seenGroups = /* @__PURE__ */ new Set();
  return value.map((group, groupIndex) => {
    if (!group || typeof group !== "object" || Array.isArray(group)) {
      throw new TypeError(`${field}[${groupIndex}] is invalid.`);
    }
    const id = requireIdentifier(group.id, `${field}[${groupIndex}].id`);
    if (seenGroups.has(id)) throw new TypeError(`${field} contains a duplicate group.`);
    seenGroups.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      throw new TypeError(`${field}[${groupIndex}] has no members.`);
    }
    const memberIDs = group.memberIDs.map((member, memberIndex) => {
      const memberID = requireIdentifier(
        member,
        `${field}[${groupIndex}].memberIDs[${memberIndex}]`
      );
      if (memberID === excludedMember || !allowedMembers.has(memberID) || seenMembers.has(memberID)) {
        throw new TypeError(`${field} contains an invalid or repeated member.`);
      }
      seenMembers.add(memberID);
      return memberID;
    });
    return { id, memberIDs };
  });
}
function groupsSatisfied(groups, attending) {
  return groups.every((group) => group.memberIDs.some((memberID) => attending.has(memberID)));
}
function resolvePrivateEvent(policyInput, responsesInput) {
  if (!policyInput || typeof policyInput !== "object" || Array.isArray(policyInput)) {
    throw new TypeError("policy is invalid.");
  }
  const eventId = requireIdentifier(policyInput.eventId, "policy.eventId");
  const hostMemberId = requireIdentifier(
    policyInput.hostMemberId ?? "host",
    "policy.hostMemberId"
  );
  if (!Array.isArray(policyInput.inviteeIds) || policyInput.inviteeIds.length > 19) {
    throw new TypeError("policy.inviteeIds is invalid.");
  }
  const inviteeIds = policyInput.inviteeIds.map(
    (value, index) => requireIdentifier(value, `policy.inviteeIds[${index}]`)
  );
  if (new Set(inviteeIds).size !== inviteeIds.length || inviteeIds.includes(hostMemberId)) {
    throw new TypeError("policy member IDs must be unique.");
  }
  const inviteeSet = new Set(inviteeIds);
  const maximumParticipants = inviteeIds.length + 1;
  const hostMinimumParticipants = requireInteger(
    policyInput.minimumParticipants,
    "policy.minimumParticipants",
    2,
    maximumParticipants
  );
  const hostRequiredGroups = normalizeGroups(
    policyInput.requiredGroups ?? [],
    "policy.requiredGroups",
    inviteeSet
  );
  if (!Array.isArray(responsesInput) || responsesInput.length > inviteeIds.length) {
    throw new TypeError("responses are invalid.");
  }
  const responses = /* @__PURE__ */ new Map();
  for (const [index, value] of responsesInput.entries()) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError(`responses[${index}] is invalid.`);
    }
    const inviteeId = requireIdentifier(value.inviteeId, `responses[${index}].inviteeId`);
    if (!inviteeSet.has(inviteeId) || responses.has(inviteeId)) {
      throw new TypeError("responses contain an unknown or duplicate invitee.");
    }
    if (value.response !== "going" && value.response !== "cant_commit") {
      throw new TypeError(`responses[${index}].response is invalid.`);
    }
    const going = value.response === "going";
    if (!going && value.minimumParticipants !== null) {
      throw new TypeError("A cant_commit response must use a null minimum.");
    }
    const minimumParticipants = going ? requireInteger(
      value.minimumParticipants,
      `responses[${index}].minimumParticipants`,
      hostMinimumParticipants,
      maximumParticipants
    ) : null;
    const requiredGroups = normalizeGroups(
      value.requiredGroups ?? [],
      `responses[${index}].requiredGroups`,
      inviteeSet,
      inviteeId
    );
    if (!going && requiredGroups.length > 0) {
      throw new TypeError("A non-attending response cannot contain conditions.");
    }
    responses.set(inviteeId, {
      inviteeId,
      response: value.response,
      minimumParticipants,
      requiredGroups
    });
  }
  let candidates = /* @__PURE__ */ new Set([
    hostMemberId,
    ...inviteeIds.filter((inviteeId) => responses.get(inviteeId)?.response === "going")
  ]);
  for (let iteration = 0; iteration <= inviteeIds.length; iteration += 1) {
    const next = /* @__PURE__ */ new Set([hostMemberId]);
    for (const inviteeId of inviteeIds) {
      const response = responses.get(inviteeId);
      if (response?.response === "going" && candidates.has(inviteeId) && candidates.size >= response.minimumParticipants && groupsSatisfied(response.requiredGroups, candidates)) {
        next.add(inviteeId);
      }
    }
    if (next.size === candidates.size && [...next].every((memberID) => candidates.has(memberID))) {
      candidates = next;
      break;
    }
    candidates = next;
  }
  if (candidates.size < hostMinimumParticipants || !groupsSatisfied(hostRequiredGroups, candidates)) {
    return { eventId, status: "not_confirmed" };
  }
  return {
    eventId,
    status: "confirmed",
    attendingMemberIds: [
      hostMemberId,
      ...inviteeIds.filter((inviteeId) => candidates.has(inviteeId))
    ]
  };
}

// ../evaluator-service/vendor/privacy-evaluator/private-response-envelope.mjs
import { webcrypto } from "node:crypto";
var { subtle } = webcrypto;
var encoder = new TextEncoder();
var decoder = new TextDecoder("utf-8", { fatal: true });
var VERSION = 1;
var CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM";
var PADDED_PLAINTEXT_BYTES = 4096;
var PAYLOAD_FRAME_BYTES = 4124;
var USER_WRAP_BYTES = 60;
var EVALUATOR_WRAP_BYTES = 157;
var EVALUATOR_PUBLIC_KEY_BYTES = 65;
var EVALUATOR_SALT_BYTES = 32;
var NONCE_BYTES = 12;
var RESPONSE_KEY_BYTES = 32;
var UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
var BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
var ENVELOPE_KEYS = [
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
  "responseSignature"
];
var DRAFT_KEYS = [
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
  "nonce"
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
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
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
  if (typeof value !== "string" || !value || !BASE64URL_PATTERN.test(value) || value.length % 4 === 1) {
    throw new TypeError(`${field} is not canonical base64url.`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedBytes || decoded.toString("base64url") !== value) {
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
  if (typeof input.evaluatorKeyId !== "string" || !/^[A-Za-z0-9._-]{1,120}$/.test(input.evaluatorKeyId)) {
    throw new TypeError("envelope.evaluatorKeyId is invalid.");
  }
  return {
    protocolVersion: VERSION,
    cipherSuite: CIPHER_SUITE,
    envelopeId: uuid(input.envelopeId, "envelope.envelopeId"),
    eventId: uuid(input.eventId, "envelope.eventId"),
    inviteeId: uuid(input.inviteeId, "envelope.inviteeId"),
    policyHash: Buffer.from(
      decodeBase64Url(input.policyHash, "envelope.policyHash", 32)
    ).toString("base64url"),
    revision: integer(input.revision, "envelope.revision", 1, 1e6),
    accountKeyEpochId: uuid(
      input.accountKeyEpochId,
      "envelope.accountKeyEpochId"
    ),
    evaluatorKeyId: input.evaluatorKeyId,
    payloadCiphertext: Buffer.from(
      decodeBase64Url(
        input.payloadCiphertext,
        "envelope.payloadCiphertext",
        PAYLOAD_FRAME_BYTES
      )
    ).toString("base64url"),
    userKeyWrap: Buffer.from(
      decodeBase64Url(input.userKeyWrap, "envelope.userKeyWrap", USER_WRAP_BYTES)
    ).toString("base64url"),
    evaluatorKeyWrap: Buffer.from(
      decodeBase64Url(
        input.evaluatorKeyWrap,
        "envelope.evaluatorKeyWrap",
        EVALUATOR_WRAP_BYTES
      )
    ).toString("base64url"),
    responseSigningPublicKey: Buffer.from(
      decodeBase64Url(
        input.responseSigningPublicKey,
        "envelope.responseSigningPublicKey",
        32
      )
    ).toString("base64url"),
    responseSignature: Buffer.from(
      decodeBase64Url(
        input.responseSignature,
        "envelope.responseSignature",
        64
      )
    ).toString("base64url")
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
    uuidBytes(envelope.accountKeyEpochId, "accountKeyEpochId")
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
    ["deriveKey"]
  );
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: arrayBuffer(salt),
      info: arrayBuffer(info)
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages
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
          tagLength: 128
        },
        key,
        arrayBuffer(frame.subarray(NONCE_BYTES))
      )
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
    allowedInviteeIds.map(
      (value, index) => uuid(value, `allowedInviteeIds[${index}]`)
    )
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
      maximumParticipants
    )
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
  const minimumParticipants = response === "going" ? integer(
    input.minimumParticipants,
    "minimumParticipants",
    hostMinimumParticipants,
    maximumParticipants
  ) : input.minimumParticipants;
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
  const seenGroups = /* @__PURE__ */ new Set();
  const seenMembers = /* @__PURE__ */ new Set();
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
        `requiredGroups[${groupIndex}].memberIDs[${memberIndex}]`
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
      decodeBase64Url(input.policyHash, "policyHash", 32)
    ).toString("base64url"),
    envelopeId: uuid(input.envelopeId, "envelopeId"),
    accountKeyEpochId: uuid(input.accountKeyEpochId, "accountKeyEpochId"),
    revision: integer(input.revision, "revision", 1, 1e6),
    response,
    minimumParticipants,
    requiredGroups,
    nonce: Buffer.from(decodeBase64Url(input.nonce, "nonce", 16)).toString("base64url")
  };
  for (const field of [
    "protocolVersion",
    "eventId",
    "inviteeId",
    "policyHash",
    "envelopeId",
    "accountKeyEpochId",
    "revision"
  ]) {
    if (draft[field] !== envelope[field]) {
      throw new TypeError(`private response ${field} does not match its envelope.`);
    }
  }
  return draft;
}
function validateEvaluatorPrivateKey(key) {
  if (!key || key.type !== "private" || key.algorithm?.name !== "ECDH" || key.algorithm?.namedCurve !== "P-256" || !key.usages.includes("deriveBits")) {
    throw new TypeError("evaluatorPrivateKey must be a P-256 ECDH private CryptoKey.");
  }
}
async function openPrivateResponseEnvelope({
  envelope: envelopeInput,
  evaluatorPrivateKey,
  expectedEvaluatorKeyId,
  allowedInviteeIds,
  hostMinimumParticipants
}) {
  const envelope = normalizeEnvelope(envelopeInput);
  validateEvaluatorPrivateKey(evaluatorPrivateKey);
  if (envelope.evaluatorKeyId !== expectedEvaluatorKeyId) {
    throw new TypeError("envelope uses the wrong evaluator key ID.");
  }
  const participantPolicy = normalizeParticipantPolicy(
    allowedInviteeIds,
    hostMinimumParticipants
  );
  const evaluatorWrap = decodeBase64Url(
    envelope.evaluatorKeyWrap,
    "evaluatorKeyWrap",
    EVALUATOR_WRAP_BYTES
  );
  const ephemeralPublicKeyBytes = evaluatorWrap.subarray(
    0,
    EVALUATOR_PUBLIC_KEY_BYTES
  );
  if (ephemeralPublicKeyBytes[0] !== 4) {
    throw new TypeError("evaluator wrap contains an invalid P-256 public key.");
  }
  const salt = evaluatorWrap.subarray(
    EVALUATOR_PUBLIC_KEY_BYTES,
    EVALUATOR_PUBLIC_KEY_BYTES + EVALUATOR_SALT_BYTES
  );
  const wrappedResponseKey = evaluatorWrap.subarray(
    EVALUATOR_PUBLIC_KEY_BYTES + EVALUATOR_SALT_BYTES
  );
  const ephemeralPublicKey = await subtle.importKey(
    "raw",
    arrayBuffer(ephemeralPublicKeyBytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedSecret = new Uint8Array(
    await subtle.deriveBits(
      { name: "ECDH", public: ephemeralPublicKey },
      evaluatorPrivateKey,
      256
    )
  );
  const keyIdBytes = encoder.encode(envelope.evaluatorKeyId);
  const evaluatorKek = await deriveAesKey(
    sharedSecret,
    salt,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-KEK-V1", envelope),
      keyIdBytes
    ),
    ["decrypt"]
  );
  sharedSecret.fill(0);
  const responseKeyBytes = await openAesFrame(
    evaluatorKek,
    wrappedResponseKey,
    concatenate(
      labeled("HERD-RSVP-EVALUATOR-WRAP-AAD-V1", envelope),
      keyIdBytes,
      ephemeralPublicKeyBytes,
      salt
    ),
    RESPONSE_KEY_BYTES
  );
  const responseKey = await subtle.importKey(
    "raw",
    arrayBuffer(responseKeyBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  responseKeyBytes.fill(0);
  const plaintext = await openAesFrame(
    responseKey,
    decodeBase64Url(
      envelope.payloadCiphertext,
      "payloadCiphertext",
      PAYLOAD_FRAME_BYTES
    ),
    labeled("HERD-RSVP-PAYLOAD-AAD-V1", envelope),
    PADDED_PLAINTEXT_BYTES
  );
  const jsonLength = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength
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
var privateResponseEnvelopeConstants = Object.freeze({
  version: VERSION,
  cipherSuite: CIPHER_SUITE,
  paddedPlaintextBytes: PADDED_PLAINTEXT_BYTES,
  payloadFrameBytes: PAYLOAD_FRAME_BYTES,
  userWrapBytes: USER_WRAP_BYTES,
  evaluatorWrapBytes: EVALUATOR_WRAP_BYTES
});

// ../evaluator-service/lib/open-valid-private-responses.mjs
async function openValidPrivateResponses(values, open) {
  const settled = await Promise.allSettled(values.map((value) => open(value)));
  return settled.flatMap(
    (result) => result.status === "fulfilled" ? [result.value] : []
  );
}

// ../evaluator-service/lib/evaluate.ts
var PROTOCOL_VERSION = 1;
var CIPHER_SUITE2 = "P256_HKDF_SHA256_AES256_GCM";
var PADDED_PLAINTEXT_BYTES2 = 4096;
var RESPONSE_AUTHORIZATION_DOMAIN = "HERD-RESPONSE-AUTHORIZATION-V1";
var MAXIMUM_INVITEES = 19;
var MAXIMUM_REQUEST_BYTES = 256 * 1024;
var UUID_PATTERN2 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
var BASE64URL_PATTERN2 = /^[A-Za-z0-9_-]+$/;
var KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,120}$/;
var encoder2 = new TextEncoder();
var fatalDecoder = new TextDecoder("utf-8", { fatal: true });
function ownedArrayBuffer(value) {
  return Uint8Array.from(value).buffer;
}
var POLICY_KEYS = [
  "protocolVersion",
  "cipherSuite",
  "policyHash",
  "canonicalDocument",
  "evaluatorKeyId",
  "evaluatorPublicKey",
  "evaluatorMeasurement",
  "releaseId",
  "paddedPlaintextBytes",
  "frozenAt"
];
var ENVELOPE_KEYS2 = [
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
  "responseSignature"
];
var EvaluatorHttpError = class extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
};
function invalidRequest() {
  throw new EvaluatorHttpError(400, "invalid_request");
}
function serviceUnavailable() {
  throw new EvaluatorHttpError(503, "service_unavailable");
}
function record2(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest();
  }
  return value;
}
function exactKeys2(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    invalidRequest();
  }
}
function boundedString(value, minimum, maximum) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    invalidRequest();
  }
  return value;
}
function identifier(value) {
  const result = boundedString(value, 1, 120);
  if (!KEY_ID_PATTERN.test(result)) invalidRequest();
  return result;
}
function uuid2(value) {
  if (typeof value !== "string" || !UUID_PATTERN2.test(value)) invalidRequest();
  return value;
}
function integer2(value, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    invalidRequest();
  }
  return value;
}
function canonicalIsoTimestamp(value) {
  if (typeof value !== "string") invalidRequest();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRequest();
  }
  return value;
}
function decodeBase64Url2(value, expectedBytes) {
  if (typeof value !== "string" || !value || !BASE64URL_PATTERN2.test(value) || value.length % 4 === 1) {
    invalidRequest();
  }
  let binary;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    invalidRequest();
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length !== expectedBytes || encodeBase64Url(bytes) !== value) {
    invalidRequest();
  }
  return bytes;
}
function encodeBase64Url(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 32768) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 32768));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder2.encode(value));
  return encodeBase64Url(new Uint8Array(digest));
}
function constantTimeEqual(left, right) {
  const maximumLength = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximumLength; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}
function requiredBinding(bindings, name, minimum, maximum) {
  const value = bindings[name];
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    serviceUnavailable();
  }
  return value;
}
function decodeConfiguredBase64Url(value) {
  if (typeof value !== "string" || !value || !BASE64URL_PATTERN2.test(value) || value.length % 4 === 1) {
    serviceUnavailable();
  }
  let binary;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    serviceUnavailable();
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length !== 32 || encodeBase64Url(bytes) !== value) {
    serviceUnavailable();
  }
  return bytes;
}
function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
function readDerLength(bytes, state) {
  if (state.offset >= bytes.length) serviceUnavailable();
  const first = bytes[state.offset++];
  if ((first & 128) === 0) return first;
  const width = first & 127;
  if (width < 1 || width > 2 || state.offset + width > bytes.length) {
    serviceUnavailable();
  }
  let length = 0;
  for (let index = 0; index < width; index += 1) {
    length = length * 256 + bytes[state.offset++];
  }
  if (length < 128 || width === 2 && length < 256) serviceUnavailable();
  return length;
}
function readDerElement(bytes, state, expectedTag) {
  if (state.offset >= bytes.length || bytes[state.offset++] !== expectedTag) {
    serviceUnavailable();
  }
  const length = readDerLength(bytes, state);
  if (length < 0 || state.offset + length > bytes.length) serviceUnavailable();
  const result = bytes.subarray(state.offset, state.offset + length);
  state.offset += length;
  return result;
}
function privateComponentsFromSec1Pem(value) {
  if (value.length < 100 || value.length > 4e3 || value.includes("\0")) {
    serviceUnavailable();
  }
  const normalized = value.replaceAll("\r\n", "\n").trim();
  const match = normalized.match(
    /^-----BEGIN EC PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END EC PRIVATE KEY-----$/u
  );
  if (!match) serviceUnavailable();
  const encoded = match[1].replaceAll("\n", "");
  let binary;
  try {
    binary = atob(encoded);
  } catch {
    serviceUnavailable();
  }
  if (btoa(binary) !== encoded) serviceUnavailable();
  const der = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const outerState = { offset: 0 };
  const sequence = readDerElement(der, outerState, 48);
  if (outerState.offset !== der.length) serviceUnavailable();
  const state = { offset: 0 };
  if (!sameBytes(readDerElement(sequence, state, 2), [1])) {
    serviceUnavailable();
  }
  const privateScalar = readDerElement(sequence, state, 4);
  if (privateScalar.length !== 32) serviceUnavailable();
  const parameters = readDerElement(sequence, state, 160);
  const parameterState = { offset: 0 };
  const curveOid = readDerElement(parameters, parameterState, 6);
  if (parameterState.offset !== parameters.length || !sameBytes(curveOid, [42, 134, 72, 206, 61, 3, 1, 7])) {
    serviceUnavailable();
  }
  const publicContainer = readDerElement(sequence, state, 161);
  const publicState = { offset: 0 };
  const bitString = readDerElement(publicContainer, publicState, 3);
  if (publicState.offset !== publicContainer.length || bitString.length !== 66 || bitString[0] !== 0 || bitString[1] !== 4 || state.offset !== sequence.length) {
    serviceUnavailable();
  }
  return {
    x: encodeBase64Url(bitString.subarray(2, 34)),
    y: encodeBase64Url(bitString.subarray(34, 66)),
    d: encodeBase64Url(privateScalar)
  };
}
function privateComponentsFromJwk(value) {
  let input;
  try {
    input = record2(JSON.parse(value));
  } catch {
    serviceUnavailable();
  }
  if (input.kty !== "EC" || input.crv !== "P-256") serviceUnavailable();
  return {
    x: encodeBase64Url(decodeConfiguredBase64Url(input.x)),
    y: encodeBase64Url(decodeConfiguredBase64Url(input.y)),
    d: encodeBase64Url(decodeConfiguredBase64Url(input.d))
  };
}
async function loadConfig(bindings) {
  const token = requiredBinding(bindings, "HERD_EVALUATOR_TOKEN", 32, 512);
  const keyId = requiredBinding(bindings, "HERD_EVALUATOR_KEY_ID", 1, 120);
  if (!KEY_ID_PATTERN.test(keyId)) serviceUnavailable();
  const measurement = requiredBinding(
    bindings,
    "HERD_EVALUATOR_MEASUREMENT",
    1,
    500
  );
  const releaseId = requiredBinding(bindings, "HERD_RELEASE_ID", 1, 200);
  const encodedJwk = bindings.HERD_EVALUATOR_PRIVATE_KEY_JWK?.trim() || null;
  const sec1Pem = bindings.HERD_EVALUATOR_PRIVATE_KEY_PEM?.trim() || null;
  if (encodedJwk === null === (sec1Pem === null)) serviceUnavailable();
  const { x, y, d } = sec1Pem ? privateComponentsFromSec1Pem(sec1Pem) : privateComponentsFromJwk(encodedJwk);
  const publicBytes = new Uint8Array(65);
  publicBytes[0] = 4;
  publicBytes.set(decodeConfiguredBase64Url(x), 1);
  publicBytes.set(decodeConfiguredBase64Url(y), 33);
  let privateKey;
  try {
    privateKey = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x,
        y,
        d,
        ext: true,
        key_ops: ["deriveBits"]
      },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
  } catch {
    serviceUnavailable();
  }
  return {
    token,
    keyId,
    privateKey,
    publicKey: encodeBase64Url(publicBytes),
    measurement,
    releaseId
  };
}
function normalizeRequiredGroups(value, memberIds) {
  if (!Array.isArray(value) || value.length > memberIds.length) invalidRequest();
  const allowed = new Set(memberIds);
  const seenGroups = /* @__PURE__ */ new Set();
  const seenMembers = /* @__PURE__ */ new Set();
  let previousGroupId = "";
  return value.map((rawGroup) => {
    const group = record2(rawGroup);
    exactKeys2(group, ["id", "memberIDs"]);
    const id = uuid2(group.id);
    if (seenGroups.has(id) || previousGroupId && id.localeCompare(previousGroupId) <= 0) {
      invalidRequest();
    }
    previousGroupId = id;
    seenGroups.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      invalidRequest();
    }
    let previousMemberId = "";
    const memberIDs = group.memberIDs.map((rawMemberId) => {
      const memberId = uuid2(rawMemberId);
      if (!allowed.has(memberId) || seenMembers.has(memberId) || previousMemberId && memberId.localeCompare(previousMemberId) <= 0) {
        invalidRequest();
      }
      previousMemberId = memberId;
      seenMembers.add(memberId);
      return memberId;
    });
    return { id, memberIDs };
  });
}
function normalizeCanonicalDocument(value) {
  const input = record2(value);
  exactKeys2(input, [
    "protocolVersion",
    "cipherSuite",
    "event",
    "members",
    "hostRules",
    "rsvpDeadline",
    "revealPolicy",
    "limits",
    "evaluator",
    "releaseId"
  ]);
  if (input.protocolVersion !== PROTOCOL_VERSION || input.cipherSuite !== CIPHER_SUITE2) {
    invalidRequest();
  }
  const rawEvent = record2(input.event);
  exactKeys2(rawEvent, [
    "id",
    "title",
    "eventDate",
    "endDate",
    "hostName",
    "locationName",
    "locationAddress",
    "eventDescription"
  ]);
  const eventDate = canonicalIsoTimestamp(rawEvent.eventDate);
  const endDate = rawEvent.endDate === null ? null : canonicalIsoTimestamp(rawEvent.endDate);
  if (endDate !== null && endDate <= eventDate) invalidRequest();
  const event = {
    id: uuid2(rawEvent.id),
    title: boundedString(rawEvent.title, 1, 120),
    eventDate,
    endDate,
    hostName: boundedString(rawEvent.hostName, 1, 80),
    locationName: boundedString(rawEvent.locationName, 0, 160),
    locationAddress: boundedString(rawEvent.locationAddress, 0, 300),
    eventDescription: boundedString(rawEvent.eventDescription, 0, 2e3)
  };
  if (!Array.isArray(input.members) || input.members.length === 0 || input.members.length > MAXIMUM_INVITEES) {
    invalidRequest();
  }
  const seenMembers = /* @__PURE__ */ new Set();
  let previousMemberId = "";
  const members = input.members.map((rawMember) => {
    const member = record2(rawMember);
    exactKeys2(member, ["id"]);
    const id = uuid2(member.id);
    if (seenMembers.has(id) || previousMemberId && id.localeCompare(previousMemberId) <= 0) {
      invalidRequest();
    }
    previousMemberId = id;
    seenMembers.add(id);
    return { id };
  });
  const memberIds = members.map(({ id }) => id);
  const rawHostRules = record2(input.hostRules);
  exactKeys2(rawHostRules, ["minimumParticipants", "requiredGroups"]);
  const hostRules = {
    minimumParticipants: integer2(
      rawHostRules.minimumParticipants,
      2,
      members.length + 1
    ),
    requiredGroups: normalizeRequiredGroups(rawHostRules.requiredGroups, memberIds)
  };
  const rsvpDeadline = canonicalIsoTimestamp(input.rsvpDeadline);
  if (rsvpDeadline >= eventDate) invalidRequest();
  if (input.revealPolicy !== "not_confirmed_or_confirmed_attendance") {
    invalidRequest();
  }
  const rawLimits = record2(input.limits);
  exactKeys2(rawLimits, [
    "maximumParticipants",
    "maximumConditionGroups",
    "maximumMembersPerGroup",
    "paddedPlaintextBytes"
  ]);
  const limits = {
    maximumParticipants: integer2(
      rawLimits.maximumParticipants,
      members.length + 1,
      members.length + 1
    ),
    maximumConditionGroups: integer2(
      rawLimits.maximumConditionGroups,
      members.length,
      members.length
    ),
    maximumMembersPerGroup: integer2(
      rawLimits.maximumMembersPerGroup,
      members.length,
      members.length
    ),
    paddedPlaintextBytes: integer2(
      rawLimits.paddedPlaintextBytes,
      PADDED_PLAINTEXT_BYTES2,
      PADDED_PLAINTEXT_BYTES2
    )
  };
  const rawEvaluator = record2(input.evaluator);
  exactKeys2(rawEvaluator, ["keyId", "publicKey", "measurement"]);
  const publicKeyBytes = decodeBase64Url2(rawEvaluator.publicKey, 65);
  if (publicKeyBytes[0] !== 4) invalidRequest();
  const evaluator = {
    keyId: identifier(rawEvaluator.keyId),
    publicKey: encodeBase64Url(publicKeyBytes),
    measurement: boundedString(rawEvaluator.measurement, 1, 500)
  };
  return {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE2,
    event,
    members,
    hostRules,
    rsvpDeadline,
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits,
    evaluator,
    releaseId: boundedString(input.releaseId, 1, 200)
  };
}
async function normalizePolicy(value, config, now) {
  const input = record2(value);
  exactKeys2(input, POLICY_KEYS);
  if (input.protocolVersion !== PROTOCOL_VERSION || input.cipherSuite !== CIPHER_SUITE2 || input.paddedPlaintextBytes !== PADDED_PLAINTEXT_BYTES2) {
    invalidRequest();
  }
  const canonicalDocument = boundedString(input.canonicalDocument, 2, 64 * 1024);
  let parsedDocument;
  try {
    parsedDocument = JSON.parse(canonicalDocument);
  } catch {
    invalidRequest();
  }
  const document = normalizeCanonicalDocument(parsedDocument);
  if (JSON.stringify(document) !== canonicalDocument) invalidRequest();
  const policyHash = encodeBase64Url(decodeBase64Url2(input.policyHash, 32));
  if (!constantTimeEqual(await sha256Base64Url(canonicalDocument), policyHash)) {
    invalidRequest();
  }
  const evaluatorPublicKeyBytes = decodeBase64Url2(input.evaluatorPublicKey, 65);
  if (evaluatorPublicKeyBytes[0] !== 4) invalidRequest();
  const evaluatorPublicKey = encodeBase64Url(evaluatorPublicKeyBytes);
  const evaluatorKeyId = identifier(input.evaluatorKeyId);
  const evaluatorMeasurement = boundedString(input.evaluatorMeasurement, 1, 500);
  const releaseId = boundedString(input.releaseId, 1, 200);
  if (evaluatorKeyId !== document.evaluator.keyId || evaluatorPublicKey !== document.evaluator.publicKey || evaluatorMeasurement !== document.evaluator.measurement || releaseId !== document.releaseId || evaluatorKeyId !== config.keyId || evaluatorPublicKey !== config.publicKey || evaluatorMeasurement !== config.measurement || releaseId !== config.releaseId) {
    invalidRequest();
  }
  const frozenAt = canonicalIsoTimestamp(input.frozenAt);
  const nowIso = now.toISOString();
  if (frozenAt > document.rsvpDeadline || frozenAt > nowIso) invalidRequest();
  return {
    policy: {
      protocolVersion: PROTOCOL_VERSION,
      cipherSuite: CIPHER_SUITE2,
      policyHash,
      canonicalDocument,
      evaluatorKeyId,
      evaluatorPublicKey,
      evaluatorMeasurement,
      releaseId,
      paddedPlaintextBytes: PADDED_PLAINTEXT_BYTES2,
      frozenAt
    },
    document
  };
}
function normalizeEnvelope2(value) {
  const input = record2(value);
  exactKeys2(input, ENVELOPE_KEYS2);
  if (input.protocolVersion !== PROTOCOL_VERSION || input.cipherSuite !== CIPHER_SUITE2) {
    invalidRequest();
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE2,
    envelopeId: uuid2(input.envelopeId),
    eventId: uuid2(input.eventId),
    inviteeId: uuid2(input.inviteeId),
    policyHash: encodeBase64Url(decodeBase64Url2(input.policyHash, 32)),
    revision: integer2(input.revision, 1, 1e6),
    accountKeyEpochId: uuid2(input.accountKeyEpochId),
    evaluatorKeyId: identifier(input.evaluatorKeyId),
    payloadCiphertext: encodeBase64Url(
      decodeBase64Url2(
        input.payloadCiphertext,
        privateResponseEnvelopeConstants.payloadFrameBytes
      )
    ),
    userKeyWrap: encodeBase64Url(
      decodeBase64Url2(
        input.userKeyWrap,
        privateResponseEnvelopeConstants.userWrapBytes
      )
    ),
    evaluatorKeyWrap: encodeBase64Url(
      decodeBase64Url2(
        input.evaluatorKeyWrap,
        privateResponseEnvelopeConstants.evaluatorWrapBytes
      )
    ),
    responseSigningPublicKey: encodeBase64Url(
      decodeBase64Url2(input.responseSigningPublicKey, 32)
    ),
    responseSignature: encodeBase64Url(
      decodeBase64Url2(input.responseSignature, 64)
    )
  };
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
    responseSigningPublicKey: envelope.responseSigningPublicKey
  });
}
function responseAuthorizationDocument(envelope, ciphertextHash) {
  return JSON.stringify({
    protocolVersion: envelope.protocolVersion,
    eventId: envelope.eventId,
    inviteeId: envelope.inviteeId,
    policyHash: envelope.policyHash,
    accountKeyEpochId: envelope.accountKeyEpochId,
    revision: envelope.revision,
    envelopeId: envelope.envelopeId,
    ciphertextHash,
    responseSigningPublicKey: envelope.responseSigningPublicKey
  });
}
async function verifyResponseAuthorization(envelope, ciphertextHash) {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer(decodeBase64Url2(envelope.responseSigningPublicKey, 32)),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      ownedArrayBuffer(decodeBase64Url2(envelope.responseSignature, 64)),
      ownedArrayBuffer(encoder2.encode(
        `${RESPONSE_AUTHORIZATION_DOMAIN}\0${responseAuthorizationDocument(
          envelope,
          ciphertextHash
        )}`
      ))
    );
    if (!valid) invalidRequest();
  } catch (error) {
    if (error instanceof EvaluatorHttpError) throw error;
    invalidRequest();
  }
}
async function normalizeSlots(value, eventId, policy, document) {
  if (!Array.isArray(value) || value.length !== document.members.length) {
    invalidRequest();
  }
  const seenEnvelopeIds = /* @__PURE__ */ new Set();
  const seenEnvelopeHashes = /* @__PURE__ */ new Set();
  return Promise.all(
    value.map(async (rawSlot, index) => {
      const input = record2(rawSlot);
      exactKeys2(input, ["inviteeId", "envelopeHash", "envelope"]);
      const inviteeId = uuid2(input.inviteeId);
      if (inviteeId !== document.members[index].id) invalidRequest();
      if (input.envelope === null || input.envelopeHash === null) {
        if (input.envelope !== null || input.envelopeHash !== null) invalidRequest();
        return { inviteeId, envelopeHash: null, envelope: null };
      }
      const envelopeHash = encodeBase64Url(decodeBase64Url2(input.envelopeHash, 32));
      const envelope = normalizeEnvelope2(input.envelope);
      if (envelope.eventId !== eventId || envelope.inviteeId !== inviteeId || envelope.policyHash !== policy.policyHash || envelope.evaluatorKeyId !== policy.evaluatorKeyId || seenEnvelopeIds.has(envelope.envelopeId) || seenEnvelopeHashes.has(envelopeHash)) {
        invalidRequest();
      }
      seenEnvelopeIds.add(envelope.envelopeId);
      seenEnvelopeHashes.add(envelopeHash);
      const computedHash = await sha256Base64Url(
        envelopeCommitmentDocument(envelope)
      );
      if (!constantTimeEqual(computedHash, envelopeHash)) invalidRequest();
      await verifyResponseAuthorization(envelope, envelopeHash);
      return { inviteeId, envelopeHash, envelope };
    })
  );
}
async function normalizeEvaluationRequest(value, config, now) {
  if (!Number.isFinite(now.getTime())) serviceUnavailable();
  const input = record2(value);
  exactKeys2(input, [
    "protocolVersion",
    "eventId",
    "policy",
    "batchHash",
    "revealAttendance",
    "slots"
  ]);
  if (input.protocolVersion !== PROTOCOL_VERSION) invalidRequest();
  const eventId = uuid2(input.eventId);
  const { policy, document } = await normalizePolicy(input.policy, config, now);
  if (document.event.id !== eventId) invalidRequest();
  if (typeof input.revealAttendance !== "boolean") invalidRequest();
  const revealAttendance = input.revealAttendance;
  if (revealAttendance !== now.toISOString() >= document.rsvpDeadline) {
    invalidRequest();
  }
  const batchHash = encodeBase64Url(decodeBase64Url2(input.batchHash, 32));
  const slots = await normalizeSlots(input.slots, eventId, policy, document);
  const batchCommitment = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    eventId,
    policyHash: policy.policyHash,
    revealAttendance,
    slots: slots.map(({ inviteeId, envelopeHash }) => ({ inviteeId, envelopeHash }))
  });
  if (!constantTimeEqual(await sha256Base64Url(batchCommitment), batchHash)) {
    invalidRequest();
  }
  return { eventId, policy, document, batchHash, revealAttendance, slots };
}
async function evaluationAuthorityClaim(value, config, now) {
  const { eventId, policy, document, batchHash, revealAttendance, slots } = await normalizeEvaluationRequest(value, config, now);
  return {
    protocolVersion: PROTOCOL_VERSION,
    eventId,
    policyHash: policy.policyHash,
    releaseId: policy.releaseId,
    evaluatorKeyId: policy.evaluatorKeyId,
    rsvpDeadline: document.rsvpDeadline,
    memberIds: document.members.map(({ id }) => id),
    batchHash,
    revealAttendance,
    slots: slots.map(({ inviteeId, envelopeHash, envelope }) => ({
      inviteeId,
      envelopeHash,
      revision: envelope?.revision ?? null,
      responseSigningPublicKey: envelope?.responseSigningPublicKey ?? null
    }))
  };
}
async function evaluate(value, config, now) {
  const { eventId, policy, document, batchHash, revealAttendance, slots } = await normalizeEvaluationRequest(value, config, now);
  const inviteeIds = document.members.map(({ id }) => id);
  const responses = await openValidPrivateResponses(
    slots.filter(
      (slot) => slot.envelope !== null
    ),
    (slot) => openPrivateResponseEnvelope({
      envelope: slot.envelope,
      evaluatorPrivateKey: config.privateKey,
      expectedEvaluatorKeyId: config.keyId,
      allowedInviteeIds: inviteeIds,
      hostMinimumParticipants: document.hostRules.minimumParticipants
    })
  );
  let resolution;
  try {
    resolution = resolvePrivateEvent(
      {
        eventId,
        hostMemberId: "host",
        inviteeIds,
        minimumParticipants: document.hostRules.minimumParticipants,
        requiredGroups: document.hostRules.requiredGroups
      },
      responses
    );
  } catch {
    invalidRequest();
  }
  const base = {
    protocolVersion: PROTOCOL_VERSION,
    eventId,
    policyHash: policy.policyHash,
    batchHash,
    evaluatorKeyId: config.keyId
  };
  if (resolution.status === "not_confirmed") {
    return { ...base, status: "not_confirmed", revealAttendance };
  }
  const attendingMemberIds = resolution.attendingMemberIds;
  if (!Array.isArray(attendingMemberIds) || attendingMemberIds[0] !== "host" || attendingMemberIds.some(
    (memberId, index) => index > 0 && memberId !== inviteeIds.filter((id) => attendingMemberIds.includes(id))[index - 1]
  ) || new Set(attendingMemberIds).size !== attendingMemberIds.length || attendingMemberIds.slice(1).some((memberId) => !inviteeIds.includes(memberId))) {
    serviceUnavailable();
  }
  return revealAttendance ? { ...base, status: "confirmed", revealAttendance, attendingMemberIds } : { ...base, status: "confirmed", revealAttendance };
}
function jsonResponse(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
}
function errorResponse(error) {
  return jsonResponse({ error: { code: error.code } }, error.status);
}

// .relay-core-build/relay.ts
var PROTOCOL_VERSION2 = 1;
var CIPHER_SUITE3 = "P256_HKDF_SHA256_AES256_GCM";
var RELAY_PLAINTEXT_BYTES = 320 * 1024;
var AES_GCM_IV_BYTES = 12;
var AES_GCM_TAG_BYTES = 16;
var RELAY_CIPHERTEXT_BYTES = AES_GCM_IV_BYTES + RELAY_PLAINTEXT_BYTES + AES_GCM_TAG_BYTES;
var MAXIMUM_INNER_REQUEST_BYTES = 256 * 1024;
var MAXIMUM_RELAY_REQUEST_BYTES = 437391;
var MAXIMUM_CAPABILITY_LIFETIME_MS = 12e4;
var MAXIMUM_ISSUED_AT_AGE_MS = 3e5;
var MAXIMUM_FUTURE_CLOCK_SKEW_MS = 3e4;
var RELAY_KEY_LABEL = "HERD-EVALUATOR-RELAY-KEY-V1\0";
var RELAY_AAD_LABEL = "HERD-EVALUATOR-RELAY-AAD-V1\0";
var RELAY_CAPABILITY_LABEL = "HERD-EVALUATOR-RELAY-CAPABILITY-V1\0";
var UUID_PATTERN3 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
var BASE64URL_PATTERN3 = /^[A-Za-z0-9_-]+$/;
var IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/;
var encoder3 = new TextEncoder();
var fatalDecoder2 = new TextDecoder("utf-8", { fatal: true });
var OUTER_KEYS = [
  "protocolVersion",
  "cipherSuite",
  "evaluatorKeyId",
  "ephemeralPublicKey",
  "salt",
  "ciphertext",
  "capabilityMac"
];
var INNER_KEYS = [
  "protocolVersion",
  "relayRequestId",
  "leaseId",
  "issuedAt",
  "expiresAt",
  "evaluationRequest"
];
var relayProtocolConstants = Object.freeze({
  protocolVersion: PROTOCOL_VERSION2,
  cipherSuite: CIPHER_SUITE3,
  plaintextBytes: RELAY_PLAINTEXT_BYTES,
  ciphertextBytes: RELAY_CIPHERTEXT_BYTES,
  maximumInnerRequestBytes: MAXIMUM_INNER_REQUEST_BYTES,
  maximumRelayRequestBytes: MAXIMUM_RELAY_REQUEST_BYTES,
  maximumCapabilityLifetimeMs: MAXIMUM_CAPABILITY_LIFETIME_MS,
  maximumIssuedAtAgeMs: MAXIMUM_ISSUED_AT_AGE_MS,
  maximumFutureClockSkewMs: MAXIMUM_FUTURE_CLOCK_SKEW_MS,
  keyLabel: RELAY_KEY_LABEL,
  aadLabel: RELAY_AAD_LABEL,
  capabilityLabel: RELAY_CAPABILITY_LABEL
});
function invalidRequest2() {
  throw new EvaluatorHttpError(400, "invalid_request");
}
function unauthorized() {
  throw new EvaluatorHttpError(401, "unauthorized");
}
function forbidden() {
  throw new EvaluatorHttpError(403, "forbidden");
}
function serviceUnavailable2() {
  throw new EvaluatorHttpError(503, "service_unavailable");
}
function record3(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest2();
  }
  return value;
}
function exactKeys3(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    invalidRequest2();
  }
}
function configuredText(bindings, name, minimum, maximum) {
  const value = bindings[name];
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    serviceUnavailable2();
  }
  return value;
}
function identifier2(value) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    invalidRequest2();
  }
  return value;
}
function uuid3(value) {
  if (typeof value !== "string" || !UUID_PATTERN3.test(value)) {
    invalidRequest2();
  }
  return value;
}
function canonicalIsoTimestamp2(value) {
  if (typeof value !== "string") invalidRequest2();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRequest2();
  }
  return value;
}
function encodeBase64Url2(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 32768) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 32768));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function decodeBase64Url3(value, expectedBytes) {
  if (typeof value !== "string" || !value || !BASE64URL_PATTERN3.test(value) || value.length % 4 === 1) {
    invalidRequest2();
  }
  let binary;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    invalidRequest2();
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length !== expectedBytes || encodeBase64Url2(bytes) !== value) {
    invalidRequest2();
  }
  return bytes;
}
function decodeConfiguredBase64Url2(value, expectedBytes) {
  try {
    return decodeBase64Url3(value, expectedBytes);
  } catch {
    serviceUnavailable2();
  }
}
function concatenate2(...values) {
  const result = new Uint8Array(
    values.reduce((total, value) => total + value.length, 0)
  );
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}
function arrayBuffer2(value) {
  return Uint8Array.from(value).buffer;
}
function constantTimeEqual2(left, right) {
  const maximumLength = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximumLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
async function sha256Base64Url2(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder3.encode(value));
  return encodeBase64Url2(new Uint8Array(digest));
}
function relayContext(request) {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt
  });
}
function capabilityDocument(request) {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
    ciphertext: request.ciphertext
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
    capabilityMac: request.capabilityMac
  });
}
function normalizeRelayRequest(value) {
  const input = record3(value);
  exactKeys3(input, OUTER_KEYS);
  if (input.protocolVersion !== PROTOCOL_VERSION2 || input.cipherSuite !== CIPHER_SUITE3) {
    invalidRequest2();
  }
  const ephemeralPublicKeyBytes = decodeBase64Url3(input.ephemeralPublicKey, 65);
  if (ephemeralPublicKeyBytes[0] !== 4) invalidRequest2();
  return {
    protocolVersion: PROTOCOL_VERSION2,
    cipherSuite: CIPHER_SUITE3,
    evaluatorKeyId: identifier2(input.evaluatorKeyId),
    ephemeralPublicKey: encodeBase64Url2(ephemeralPublicKeyBytes),
    salt: encodeBase64Url2(decodeBase64Url3(input.salt, 32)),
    ciphertext: encodeBase64Url2(
      decodeBase64Url3(input.ciphertext, RELAY_CIPHERTEXT_BYTES)
    ),
    capabilityMac: encodeBase64Url2(decodeBase64Url3(input.capabilityMac, 32))
  };
}
async function verifyCapability(request, configuredToken) {
  let key;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      encoder3.encode(configuredToken),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } catch {
    serviceUnavailable2();
  }
  const input = concatenate2(
    encoder3.encode(RELAY_CAPABILITY_LABEL),
    encoder3.encode(capabilityDocument(request))
  );
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, arrayBuffer2(input))
  );
  const supplied = decodeBase64Url3(request.capabilityMac, 32);
  if (!constantTimeEqual2(expected, supplied)) unauthorized();
}
async function decryptRelayFrame(request, evaluatorPrivateKey) {
  const ephemeralPublicKeyBytes = decodeBase64Url3(
    request.ephemeralPublicKey,
    65
  );
  let ephemeralPublicKey;
  let sharedSecret;
  try {
    ephemeralPublicKey = await crypto.subtle.importKey(
      "raw",
      arrayBuffer2(ephemeralPublicKeyBytes),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    sharedSecret = await crypto.subtle.deriveBits(
      { name: "ECDH", public: ephemeralPublicKey },
      evaluatorPrivateKey,
      256
    );
  } catch {
    invalidRequest2();
  }
  let baseKey;
  let aesKey;
  const context2 = encoder3.encode(relayContext(request));
  try {
    baseKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveKey"]
    );
    aesKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: arrayBuffer2(decodeBase64Url3(request.salt, 32)),
        info: arrayBuffer2(
          concatenate2(encoder3.encode(RELAY_KEY_LABEL), context2)
        )
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  } catch {
    serviceUnavailable2();
  }
  const sealed = decodeBase64Url3(request.ciphertext, RELAY_CIPHERTEXT_BYTES);
  const iv = sealed.subarray(0, AES_GCM_IV_BYTES);
  const ciphertextAndTag = sealed.subarray(AES_GCM_IV_BYTES);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: arrayBuffer2(iv),
        additionalData: arrayBuffer2(
          concatenate2(encoder3.encode(RELAY_AAD_LABEL), context2)
        ),
        tagLength: 128
      },
      aesKey,
      arrayBuffer2(ciphertextAndTag)
    );
    const bytes = new Uint8Array(plaintext);
    if (bytes.length !== RELAY_PLAINTEXT_BYTES) invalidRequest2();
    return bytes;
  } catch (error) {
    if (error instanceof EvaluatorHttpError) throw error;
    invalidRequest2();
  }
}
function normalizeInnerRelayRequest(frame, now) {
  if (frame.length !== RELAY_PLAINTEXT_BYTES || !Number.isFinite(now.getTime())) {
    serviceUnavailable2();
  }
  const length = new DataView(
    frame.buffer,
    frame.byteOffset,
    frame.byteLength
  ).getUint32(0, false);
  if (length < 2 || length > MAXIMUM_INNER_REQUEST_BYTES || length > frame.length - 4) {
    invalidRequest2();
  }
  for (let index = 4 + length; index < frame.length; index += 1) {
    if (frame[index] !== 0) invalidRequest2();
  }
  let canonicalDocument;
  let parsed;
  try {
    canonicalDocument = fatalDecoder2.decode(frame.subarray(4, 4 + length));
    parsed = JSON.parse(canonicalDocument);
  } catch {
    invalidRequest2();
  }
  if (JSON.stringify(parsed) !== canonicalDocument) invalidRequest2();
  const input = record3(parsed);
  exactKeys3(input, INNER_KEYS);
  if (input.protocolVersion !== PROTOCOL_VERSION2) invalidRequest2();
  const evaluationRequest = record3(input.evaluationRequest);
  const issuedAt = canonicalIsoTimestamp2(input.issuedAt);
  const expiresAt = canonicalIsoTimestamp2(input.expiresAt);
  const issuedAtMs = Date.parse(issuedAt);
  const expiresAtMs = Date.parse(expiresAt);
  const nowMs = now.getTime();
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAXIMUM_CAPABILITY_LIFETIME_MS || issuedAtMs > nowMs + MAXIMUM_FUTURE_CLOCK_SKEW_MS || nowMs - issuedAtMs > MAXIMUM_ISSUED_AT_AGE_MS || nowMs >= expiresAtMs) {
    unauthorized();
  }
  return {
    protocolVersion: PROTOCOL_VERSION2,
    relayRequestId: uuid3(input.relayRequestId),
    leaseId: uuid3(input.leaseId),
    issuedAt,
    expiresAt,
    evaluationRequest
  };
}
async function loadSigningConfig(bindings) {
  const keyId = configuredText(
    bindings,
    "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID",
    1,
    120
  );
  if (!IDENTIFIER_PATTERN.test(keyId)) serviceUnavailable2();
  const encodedJwk = configuredText(
    bindings,
    "HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK",
    50,
    4e3
  );
  let input;
  try {
    input = record3(JSON.parse(encodedJwk));
  } catch {
    serviceUnavailable2();
  }
  if (input.kty !== "EC" || input.crv !== "P-256") serviceUnavailable2();
  const x = encodeBase64Url2(decodeConfiguredBase64Url2(input.x, 32));
  const y = encodeBase64Url2(decodeConfiguredBase64Url2(input.y, 32));
  const d = encodeBase64Url2(decodeConfiguredBase64Url2(input.d, 32));
  let privateKey;
  try {
    privateKey = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x,
        y,
        d,
        ext: false,
        key_ops: ["sign"]
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  } catch {
    serviceUnavailable2();
  }
  return { keyId, privateKey };
}
function readDerLength2(bytes, state) {
  if (state.offset >= bytes.length) serviceUnavailable2();
  const first = bytes[state.offset++];
  if ((first & 128) === 0) return first;
  const width = first & 127;
  if (width < 1 || width > 2 || state.offset + width > bytes.length) {
    serviceUnavailable2();
  }
  let length = 0;
  for (let index = 0; index < width; index += 1) {
    length = length * 256 + bytes[state.offset++];
  }
  if (length < 128 || width === 2 && length < 256) serviceUnavailable2();
  return length;
}
function readDerInteger(bytes, state) {
  if (state.offset >= bytes.length || bytes[state.offset++] !== 2) {
    serviceUnavailable2();
  }
  const length = readDerLength2(bytes, state);
  if (length < 1 || length > 33 || state.offset + length > bytes.length) {
    serviceUnavailable2();
  }
  let value = bytes.subarray(state.offset, state.offset + length);
  state.offset += length;
  if ((value[0] & 128) !== 0) serviceUnavailable2();
  if (value.length === 33) {
    if (value[0] !== 0 || (value[1] & 128) === 0) serviceUnavailable2();
    value = value.subarray(1);
  } else if (value.length > 1 && value[0] === 0 && (value[1] & 128) === 0) {
    serviceUnavailable2();
  }
  const result = new Uint8Array(32);
  result.set(value, 32 - value.length);
  return result;
}
function normalizeEcdsaSignature(signature) {
  if (signature.length === 64) return Uint8Array.from(signature);
  const state = { offset: 0 };
  if (signature[state.offset++] !== 48) serviceUnavailable2();
  const sequenceLength = readDerLength2(signature, state);
  if (state.offset + sequenceLength !== signature.length) serviceUnavailable2();
  const sequenceEnd = state.offset + sequenceLength;
  const r = readDerInteger(signature, state);
  const s = readDerInteger(signature, state);
  if (state.offset !== sequenceEnd) serviceUnavailable2();
  return concatenate2(r, s);
}
async function signResultAttestation(signingConfig, relayRequestHash, inner, result, evaluatedAt) {
  const canonicalDocument = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION2,
    signingKeyId: signingConfig.keyId,
    relayRequestHash,
    relayRequestId: inner.relayRequestId,
    leaseId: inner.leaseId,
    evaluatedAt,
    result
  });
  let signature;
  try {
    signature = normalizeEcdsaSignature(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          signingConfig.privateKey,
          encoder3.encode(canonicalDocument)
        )
      )
    );
  } catch (error) {
    if (error instanceof EvaluatorHttpError) throw error;
    serviceUnavailable2();
  }
  if (signature.length !== 64) serviceUnavailable2();
  return {
    protocolVersion: PROTOCOL_VERSION2,
    signingKeyId: signingConfig.keyId,
    evaluatedAt,
    canonicalDocument,
    signature: encodeBase64Url2(signature)
  };
}
async function readBoundedBody(request, maximumBytes) {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > maximumBytes) {
      throw new EvaluatorHttpError(413, "request_too_large");
    }
  }
  if (!request.body) invalidRequest2();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new EvaluatorHttpError(413, "request_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) invalidRequest2();
  return concatenate2(...chunks);
}
function configuredAllowedOrigin(bindings) {
  const value = configuredText(
    bindings,
    "HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN",
    8,
    300
  );
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    serviceUnavailable2();
  }
  const localHttp = parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
  if (parsed.protocol !== "https:" && !localHttp || parsed.origin !== value || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username || parsed.password) {
    serviceUnavailable2();
  }
  return value;
}
function requestOrigin(request, allowedOrigin, required) {
  const origin = request.headers.get("origin");
  if (origin === null) {
    if (required) forbidden();
    return null;
  }
  if (origin !== allowedOrigin) forbidden();
  return origin;
}
function withCors(response, origin) {
  if (origin !== null) {
    response.headers.set("access-control-allow-origin", origin);
    response.headers.set("vary", "Origin");
  }
  return response;
}
async function handleRelayOptionsRequest(request, bindings) {
  let origin = null;
  try {
    if (request.method !== "OPTIONS") invalidRequest2();
    const allowedOrigin = configuredAllowedOrigin(bindings);
    origin = requestOrigin(request, allowedOrigin, true);
    if (request.headers.get("access-control-request-method") !== "POST") {
      forbidden();
    }
    const requestedHeaders = (request.headers.get(
      "access-control-request-headers"
    ) ?? "").split(",").map((value) => value.trim().toLowerCase()).filter(Boolean).sort();
    const allowedHeaders = /* @__PURE__ */ new Set([
      "cache-control",
      "content-type",
      "pragma",
      "x-herd-client-platform",
      "x-herd-request-id"
    ]);
    if (!requestedHeaders.includes("content-type") || new Set(requestedHeaders).size !== requestedHeaders.length || requestedHeaders.some((header) => !allowedHeaders.has(header)) || request.headers.has("access-control-request-private-network")) {
      forbidden();
    }
    return withCors(
      new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-methods": "POST",
          "access-control-allow-headers": "content-type, cache-control, pragma, x-herd-client-platform, x-herd-request-id",
          "access-control-max-age": "600",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        }
      }),
      origin
    );
  } catch (error) {
    const response = error instanceof EvaluatorHttpError ? errorResponse(error) : errorResponse(new EvaluatorHttpError(503, "service_unavailable"));
    return withCors(response, origin);
  }
}
async function handleRelayRequest(request, bindings, now = /* @__PURE__ */ new Date(), evaluationAuthorizer, configOverride, signingConfigOverride) {
  let origin = null;
  try {
    if (request.method !== "POST") invalidRequest2();
    const allowedOrigin = configuredAllowedOrigin(bindings);
    origin = requestOrigin(request, allowedOrigin, false);
    const mediaType = (request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
    if (mediaType !== "application/json") invalidRequest2();
    const bytes = await readBoundedBody(request, MAXIMUM_RELAY_REQUEST_BYTES);
    let parsed;
    try {
      parsed = JSON.parse(fatalDecoder2.decode(bytes));
    } catch {
      invalidRequest2();
    }
    const relayRequest = normalizeRelayRequest(parsed);
    const normalizedJson = normalizedRelayJson(relayRequest);
    const config = configOverride ?? await loadConfig(bindings);
    if (relayRequest.evaluatorKeyId !== config.keyId) invalidRequest2();
    await verifyCapability(relayRequest, config.token);
    const relayRequestHash = await sha256Base64Url2(normalizedJson);
    const frame = await decryptRelayFrame(relayRequest, config.privateKey);
    const inner = normalizeInnerRelayRequest(frame, now);
    if (evaluationAuthorizer) {
      const claim = await evaluationAuthorityClaim(
        inner.evaluationRequest,
        config,
        now
      );
      await evaluationAuthorizer(claim);
    }
    const result = await evaluate(inner.evaluationRequest, config, now);
    const evaluatedAt = now.toISOString();
    const signingConfig = signingConfigOverride ?? await loadSigningConfig(bindings);
    const attestation = await signResultAttestation(
      signingConfig,
      relayRequestHash,
      inner,
      result,
      evaluatedAt
    );
    return withCors(
      jsonResponse(
        {
          protocolVersion: PROTOCOL_VERSION2,
          relayRequestHash,
          relayRequestId: inner.relayRequestId,
          leaseId: inner.leaseId,
          result,
          attestation
        },
        200
      ),
      origin
    );
  } catch (error) {
    const response = error instanceof EvaluatorHttpError ? errorResponse(error) : errorResponse(new EvaluatorHttpError(503, "service_unavailable"));
    return withCors(response, origin);
  }
}
export {
  handleRelayOptionsRequest,
  handleRelayRequest,
  normalizeEcdsaSignature,
  relayProtocolConstants
};
