// Generated from invitee-web/lib/backend/resolutions.ts for compatibility testing; do not edit by hand.

// invitee-web/lib/privacy/protocol.ts
var PRIVATE_RESPONSE_PROTOCOL_VERSION = 1;
function publicRuntimeValue(key) {
  if (typeof window !== "undefined") {
    return window.__HERD_PUBLIC_RUNTIME_CONFIG__?.[key];
  }
  return process.env[`NEXT_PUBLIC_${key}`];
}
var PRIVATE_RESPONSE_CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM";
var PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES = 4096;
var PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES = 4124;
var PRIVATE_RESPONSE_USER_WRAP_BYTES = 60;
var PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES = 157;
var PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN = "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1";
var PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1";
var PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
var PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1";
var PRIVATE_RESPONSE_AUTHORIZATION_DOMAIN = "HERD-RESPONSE-AUTHORIZATION-V1";
var PRIVATE_RESPONSE_SIGNING_DERIVATION_LABEL = "HERD-RESPONSE-SIGNING-SEED-V1";
var PRIVATE_RESPONSE_SIGNATURE_BYTES = 64;
var PRIVATE_RESPONSE_HASH_BYTES = 32;
var PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES = 32;
var PRIVATE_RESPONSE_LOG_ID = "herd-response-log-v1";
function canonicalPrivateResponseLogHeadPayload(head) {
  return JSON.stringify({
    protocolVersion: head.protocolVersion,
    logId: head.logId,
    treeSize: head.treeSize,
    headEntryHash: head.headEntryHash,
    generatedAt: head.generatedAt,
    signingKeyId: head.signingKeyId
  });
}
function domainSeparatedUtf8(domain, canonicalPayload) {
  return new TextEncoder().encode(`${domain}\0${canonicalPayload}`);
}
var UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
var POLICY_HASH_BYTES = 32;
var EVALUATOR_PUBLIC_KEY_BYTES = 65;
function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
function requireExactKeys(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${field} contains unsupported fields.`);
  }
}
function requireUuid(value, field) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError(`${field} must be a UUID.`);
  }
  return value.toLowerCase();
}
function requireInteger(value, field) {
  if (!Number.isInteger(value) || value < 1 || value > 1e6) {
    throw new TypeError(`${field} must be a positive integer.`);
  }
  return value;
}
function requireKeyId(value, field) {
  if (typeof value !== "string" || value.length < 1 || value.length > 120 || !/^[A-Za-z0-9._-]+$/.test(value)) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}
function base64UrlDecodedLength(value) {
  if (!value || !BASE64URL_PATTERN.test(value) || value.includes("=")) return -1;
  const remainder = value.length % 4;
  if (remainder === 1) return -1;
  return Math.floor(value.length * 6 / 8);
}
function requireBase64UrlBytes(value, field, expectedBytes) {
  if (typeof value !== "string" || base64UrlDecodedLength(value) !== expectedBytes) {
    throw new TypeError(`${field} must encode exactly ${expectedBytes} bytes.`);
  }
  const decoded = base64UrlToBytes(value);
  if (decoded.length !== expectedBytes || bytesToBase64Url(decoded) !== value) {
    throw new TypeError(`${field} must use canonical unpadded base64url.`);
  }
  return value;
}
function normalizePrivateResponseUnsignedEnvelope(value) {
  if (!isRecord(value)) throw new TypeError("envelope must be an object.");
  requireExactKeys(
    value,
    [
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
      "responseSigningPublicKey"
    ],
    "envelope"
  );
  if (value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION) {
    throw new TypeError("envelope.protocolVersion is unsupported.");
  }
  if (value.cipherSuite !== PRIVATE_RESPONSE_CIPHER_SUITE) {
    throw new TypeError("envelope.cipherSuite is unsupported.");
  }
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    envelopeId: requireUuid(value.envelopeId, "envelope.envelopeId"),
    eventId: requireUuid(value.eventId, "envelope.eventId"),
    inviteeId: requireUuid(value.inviteeId, "envelope.inviteeId"),
    policyHash: requireBase64UrlBytes(
      value.policyHash,
      "envelope.policyHash",
      POLICY_HASH_BYTES
    ),
    revision: requireInteger(value.revision, "envelope.revision"),
    accountKeyEpochId: requireUuid(
      value.accountKeyEpochId,
      "envelope.accountKeyEpochId"
    ),
    evaluatorKeyId: requireKeyId(
      value.evaluatorKeyId,
      "envelope.evaluatorKeyId"
    ),
    payloadCiphertext: requireBase64UrlBytes(
      value.payloadCiphertext,
      "envelope.payloadCiphertext",
      PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES
    ),
    userKeyWrap: requireBase64UrlBytes(
      value.userKeyWrap,
      "envelope.userKeyWrap",
      PRIVATE_RESPONSE_USER_WRAP_BYTES
    ),
    evaluatorKeyWrap: requireBase64UrlBytes(
      value.evaluatorKeyWrap,
      "envelope.evaluatorKeyWrap",
      PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES
    ),
    responseSigningPublicKey: requireBase64UrlBytes(
      value.responseSigningPublicKey,
      "envelope.responseSigningPublicKey",
      PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES
    )
  };
}
function normalizePrivateResponseEnvelope(value) {
  if (!isRecord(value)) throw new TypeError("envelope must be an object.");
  requireExactKeys(
    value,
    [
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
    ],
    "envelope"
  );
  const {
    responseSignature: _responseSignature,
    ...unsignedInput
  } = value;
  void _responseSignature;
  return {
    ...normalizePrivateResponseUnsignedEnvelope(unsignedInput),
    responseSignature: requireBase64UrlBytes(
      value.responseSignature,
      "envelope.responseSignature",
      PRIVATE_RESPONSE_SIGNATURE_BYTES
    )
  };
}
function normalizeEvaluatorPublicKey(value) {
  const normalized = requireBase64UrlBytes(
    value,
    "evaluatorPublicKey",
    EVALUATOR_PUBLIC_KEY_BYTES
  );
  if (base64UrlToBytes(normalized)[0] !== 4) {
    throw new TypeError("evaluatorPublicKey must be an uncompressed P-256 point.");
  }
  return normalized;
}
function canonicalEnvelopeJson(envelope) {
  const { responseSignature: _responseSignature, ...unsigned } = envelope;
  void _responseSignature;
  return JSON.stringify(normalizePrivateResponseUnsignedEnvelope(unsigned));
}
function canonicalPrivateResponseAuthorizationPayload(envelope, ciphertextHash) {
  const normalized = normalizePrivateResponseUnsignedEnvelope(
    Object.fromEntries(
      Object.entries(envelope).filter(([key]) => key !== "responseSignature")
    )
  );
  return JSON.stringify({
    protocolVersion: normalized.protocolVersion,
    eventId: normalized.eventId,
    inviteeId: normalized.inviteeId,
    policyHash: normalized.policyHash,
    accountKeyEpochId: normalized.accountKeyEpochId,
    revision: normalized.revision,
    envelopeId: normalized.envelopeId,
    ciphertextHash: requireBase64UrlBytes(
      ciphertextHash,
      "ciphertextHash",
      PRIVATE_RESPONSE_HASH_BYTES
    ),
    responseSigningPublicKey: normalized.responseSigningPublicKey
  });
}
function privateResponseAuthorizationBytes(envelope, ciphertextHash) {
  return domainSeparatedUtf8(
    PRIVATE_RESPONSE_AUTHORIZATION_DOMAIN,
    canonicalPrivateResponseAuthorizationPayload(envelope, ciphertextHash)
  );
}
function privateResponseContext(envelope) {
  const result = new Uint8Array(101);
  let offset = 0;
  result[offset] = PRIVATE_RESPONSE_PROTOCOL_VERSION;
  offset += 1;
  for (const value of [
    uuidToBytes(envelope.eventId),
    uuidToBytes(envelope.inviteeId),
    base64UrlToBytes(envelope.policyHash),
    uuidToBytes(envelope.envelopeId),
    uuidToBytes(envelope.accountKeyEpochId)
  ]) {
    result.set(value, offset);
    offset += value.length;
  }
  new DataView(result.buffer).setUint32(offset, envelope.revision, false);
  return result;
}
function privateResponseAad(purpose, envelope) {
  const labels = {
    payload: "HERD-RSVP-PAYLOAD-AAD-V1",
    "user-key-wrap": "HERD-RSVP-USER-WRAP-AAD-V1",
    "evaluator-key-wrap": "HERD-RSVP-EVALUATOR-WRAP-AAD-V1",
    "user-key-derivation": "HERD-RSVP-USER-KEK-V1",
    "evaluator-key-derivation": "HERD-RSVP-EVALUATOR-KEK-V1"
  };
  return concatenateBytes(
    new TextEncoder().encode(labels[purpose]),
    new Uint8Array([0]),
    privateResponseContext(envelope)
  );
}
function uuidToBytes(value) {
  const normalized = requireUuid(value, "UUID").replaceAll("-", "");
  const bytes = new Uint8Array(16);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
function base64UrlToBytes(value) {
  if (base64UrlDecodedLength(value) < 0) throw new TypeError("Invalid base64url value.");
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function bytesToBase64Url(value) {
  let binary = "";
  for (let index = 0; index < value.length; index += 32768) {
    binary += String.fromCharCode(...value.subarray(index, index + 32768));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function concatenateBytes(...values) {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

// invitee-web/lib/privacy/trust-verification.ts
var PrivateResponseTrustError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "PrivateResponseTrustError";
  }
};
function ownedArrayBuffer(value) {
  return Uint8Array.from(value).buffer;
}
function cryptoApi() {
  if (!globalThis.crypto?.subtle) {
    throw new PrivateResponseTrustError("This device cannot verify Herd trust proofs.");
  }
  return globalThis.crypto;
}
function canonicalBase64Url(value, bytes, field) {
  if (typeof value !== "string") {
    throw new PrivateResponseTrustError(`${field} is missing.`);
  }
  let decoded;
  try {
    decoded = base64UrlToBytes(value);
  } catch {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  if (decoded.length !== bytes || bytesToBase64Url(decoded) !== value) {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  return value;
}
async function verifyP256(pin, domain, canonicalPayload, signature) {
  let publicKey;
  try {
    publicKey = normalizeEvaluatorPublicKey(pin.publicKey);
  } catch {
    throw new PrivateResponseTrustError("This Herd release has an invalid trust key.");
  }
  const signatureValue = canonicalBase64Url(
    signature,
    PRIVATE_RESPONSE_SIGNATURE_BYTES,
    "Trust signature"
  );
  try {
    const key = await cryptoApi().subtle.importKey(
      "raw",
      ownedArrayBuffer(base64UrlToBytes(publicKey)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    return cryptoApi().subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      ownedArrayBuffer(base64UrlToBytes(signatureValue)),
      ownedArrayBuffer(domainSeparatedUtf8(domain, canonicalPayload))
    );
  } catch (error) {
    if (error instanceof PrivateResponseTrustError) throw error;
    return false;
  }
}
function configuredPolicySigningPin() {
  const keyId = publicRuntimeValue("HERD_EVALUATOR_POLICY_SIGNING_KEY_ID");
  const publicKey = publicRuntimeValue("HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY");
  return keyId && publicKey ? { keyId, publicKey } : null;
}
async function verifyEventPolicyCertification(policy, pin) {
  if (!policy.policySigningKeyId || policy.policySigningKeyId !== pin.keyId || !policy.policySignature || !await verifyP256(
    pin,
    PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
    policy.canonicalDocument,
    policy.policySignature
  )) {
    throw new PrivateResponseTrustError(
      "The event policy is not certified by this Herd release."
    );
  }
}

// invitee-web/lib/privacy/private-response-crypto.ts
var AES_GCM_NONCE_BYTES = 12;
var AES_GCM_TAG_BITS = 128;
var RESPONSE_KEY_BYTES = 32;
var POLICY_HASH_BYTES2 = 32;
var EVALUATOR_PUBLIC_KEY_BYTES2 = 65;
var EVALUATOR_SALT_BYTES = 32;
var DRAFT_NONCE_BYTES = 16;
var MAX_PARTICIPANTS = 20;
var ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  48,
  46,
  2,
  1,
  0,
  48,
  5,
  6,
  3,
  43,
  101,
  112,
  4,
  34,
  4,
  32
]);
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder("utf-8", { fatal: true });
var bakedEvaluatorKeyId = publicRuntimeValue("HERD_EVALUATOR_KEY_ID");
var bakedEvaluatorPublicKey = publicRuntimeValue("HERD_EVALUATOR_PUBLIC_KEY");
var PrivateResponseCryptoError = class extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "PrivateResponseCryptoError";
    this.canSwitchDevice = options.canSwitchDevice ?? false;
  }
};
function cryptoApi2() {
  const value = globalThis.crypto;
  if (!value?.subtle || typeof value.getRandomValues !== "function") {
    throw new PrivateResponseCryptoError(
      "Private responses require a browser with Web Crypto support."
    );
  }
  return value;
}
function toArrayBuffer(value) {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength
  );
}
function randomBytes(length) {
  return cryptoApi2().getRandomValues(new Uint8Array(length));
}
function randomUuid() {
  const bytes = randomBytes(16);
  bytes[6] = bytes[6] & 15 | 64;
  bytes[8] = bytes[8] & 63 | 128;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
function strictBase64UrlBytes(value, expectedLength, field) {
  let bytes;
  try {
    bytes = base64UrlToBytes(value);
  } catch {
    throw new PrivateResponseCryptoError(`${field} is not valid base64url.`);
  }
  if (bytes.length !== expectedLength || bytesToBase64Url(bytes) !== value) {
    throw new PrivateResponseCryptoError(
      `${field} must be canonical base64url for ${expectedLength} bytes.`
    );
  }
  return bytes;
}
function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}
function requireRecord(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PrivateResponseCryptoError(`${field} is invalid.`);
  }
  return value;
}
function requireExactKeys2(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new PrivateResponseCryptoError(`${field} contains unsupported fields.`);
  }
}
function normalizeUuid(value, field) {
  if (typeof value !== "string") {
    throw new PrivateResponseCryptoError(`${field} must be a UUID.`);
  }
  try {
    uuidToBytes(value);
  } catch {
    throw new PrivateResponseCryptoError(`${field} must be a UUID.`);
  }
  return value.toLowerCase();
}
function boundedInteger(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new PrivateResponseCryptoError(
      `${field} must be an integer from ${minimum} to ${maximum}.`
    );
  }
  return value;
}
function normalizeDraft(value, allowedInviteeIds, frozenPolicy) {
  const input = requireRecord(value, "Private response");
  requireExactKeys2(
    input,
    [
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
    ],
    "Private response"
  );
  if (input.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION) {
    throw new PrivateResponseCryptoError("The private-response version is unsupported.");
  }
  const eventId = normalizeUuid(input.eventId, "eventId");
  const inviteeId = normalizeUuid(input.inviteeId, "inviteeId");
  const envelopeId = normalizeUuid(input.envelopeId, "envelopeId");
  const accountKeyEpochId = normalizeUuid(
    input.accountKeyEpochId,
    "accountKeyEpochId"
  );
  if (typeof input.policyHash !== "string") {
    throw new PrivateResponseCryptoError("policyHash is invalid.");
  }
  strictBase64UrlBytes(input.policyHash, POLICY_HASH_BYTES2, "policyHash");
  if (!Number.isInteger(input.revision) || input.revision < 1 || input.revision > 1e6) {
    throw new PrivateResponseCryptoError("revision is invalid.");
  }
  if (input.response !== "going" && input.response !== "cant_commit") {
    throw new PrivateResponseCryptoError("response is invalid.");
  }
  const minimumParticipants = input.minimumParticipants;
  if (input.response === "going") {
    if (!Number.isInteger(minimumParticipants)) {
      throw new PrivateResponseCryptoError(
        "A going response must include an integer minimum participant count."
      );
    }
    if (minimumParticipants < frozenPolicy.hostMinimumParticipants) {
      throw new PrivateResponseCryptoError(
        "The response minimum cannot be below the frozen host minimum."
      );
    }
    if (minimumParticipants > frozenPolicy.maximumParticipants) {
      throw new PrivateResponseCryptoError(
        "The response minimum cannot exceed the frozen participant maximum."
      );
    }
  }
  if (!Array.isArray(input.requiredGroups) || input.requiredGroups.length > MAX_PARTICIPANTS) {
    throw new PrivateResponseCryptoError("requiredGroups is invalid.");
  }
  if (!Array.isArray(allowedInviteeIds)) {
    throw new PrivateResponseCryptoError("allowedInviteeIds is invalid.");
  }
  const normalizedAllowedInviteeIds = allowedInviteeIds.map(
    (id, index) => normalizeUuid(id, `allowedInviteeIds[${index}]`)
  );
  const allowed = new Set(normalizedAllowedInviteeIds);
  const frozenInvitees = new Set(frozenPolicy.inviteeIds);
  if (allowed.size !== normalizedAllowedInviteeIds.length || allowed.size + 1 !== frozenPolicy.maximumParticipants || allowed.size !== frozenInvitees.size || normalizedAllowedInviteeIds.some((id) => !frozenInvitees.has(id))) {
    throw new PrivateResponseCryptoError(
      "The invited people do not match the frozen event policy."
    );
  }
  if (eventId !== frozenPolicy.eventId) {
    throw new PrivateResponseCryptoError(
      "The response event does not match the frozen event policy."
    );
  }
  if (!allowed.has(inviteeId)) {
    throw new PrivateResponseCryptoError(
      "The respondent is not in the frozen event policy."
    );
  }
  const seenMembers = /* @__PURE__ */ new Set();
  const seenGroups = /* @__PURE__ */ new Set();
  const requiredGroups = input.requiredGroups.map((rawGroup, groupIndex) => {
    const group = requireRecord(rawGroup, `requiredGroups[${groupIndex}]`);
    requireExactKeys2(group, ["id", "memberIDs"], `requiredGroups[${groupIndex}]`);
    const id = normalizeUuid(group.id, `requiredGroups[${groupIndex}].id`);
    if (seenGroups.has(id)) {
      throw new PrivateResponseCryptoError("Condition group IDs must be unique.");
    }
    seenGroups.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length < 1 || group.memberIDs.length > MAX_PARTICIPANTS) {
      throw new PrivateResponseCryptoError(
        `requiredGroups[${groupIndex}].memberIDs is invalid.`
      );
    }
    const memberIDs = group.memberIDs.map((rawMemberId, memberIndex) => {
      const memberId = normalizeUuid(
        rawMemberId,
        `requiredGroups[${groupIndex}].memberIDs[${memberIndex}]`
      );
      if (memberId === inviteeId || !allowed.has(memberId) || seenMembers.has(memberId)) {
        throw new PrivateResponseCryptoError(
          "Each condition member must be another invited person and may appear only once."
        );
      }
      seenMembers.add(memberId);
      return memberId;
    });
    return { id, memberIDs };
  });
  if (input.response === "cant_commit" && (minimumParticipants !== null || requiredGroups.length > 0)) {
    throw new PrivateResponseCryptoError(
      "A can\u2019t-commit response cannot contain attendance conditions."
    );
  }
  if (typeof input.nonce !== "string") {
    throw new PrivateResponseCryptoError("nonce is invalid.");
  }
  strictBase64UrlBytes(input.nonce, DRAFT_NONCE_BYTES, "nonce");
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId,
    inviteeId,
    policyHash: input.policyHash,
    envelopeId,
    accountKeyEpochId,
    revision: input.revision,
    response: input.response,
    minimumParticipants,
    requiredGroups,
    nonce: input.nonce
  };
}
async function assertTrustedPolicy(policy, serverVerifiedTrust) {
  if (policy.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || policy.cipherSuite !== PRIVATE_RESPONSE_CIPHER_SUITE || policy.paddedPlaintextBytes !== PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES) {
    throw new PrivateResponseCryptoError("This event uses an unsupported privacy policy.");
  }
  const trustedEvaluatorKeyId = serverVerifiedTrust?.evaluatorKeyId ?? bakedEvaluatorKeyId;
  const trustedEvaluatorPublicKey = serverVerifiedTrust?.evaluatorPublicKey ?? bakedEvaluatorPublicKey;
  if (!trustedEvaluatorKeyId || !trustedEvaluatorPublicKey) {
    throw new PrivateResponseCryptoError(
      "Private responses are unavailable because this Herd release has no trusted evaluator configured."
    );
  }
  let evaluatorPublicKey2;
  let expectedPublicKey;
  try {
    evaluatorPublicKey2 = normalizeEvaluatorPublicKey(policy.evaluatorPublicKey);
    expectedPublicKey = normalizeEvaluatorPublicKey(trustedEvaluatorPublicKey);
  } catch {
    throw new PrivateResponseCryptoError("The trusted evaluator key is malformed.");
  }
  const evaluatorBytes = strictBase64UrlBytes(
    evaluatorPublicKey2,
    EVALUATOR_PUBLIC_KEY_BYTES2,
    "evaluatorPublicKey"
  );
  const expectedBytes = strictBase64UrlBytes(
    expectedPublicKey,
    EVALUATOR_PUBLIC_KEY_BYTES2,
    "trusted evaluator public key"
  );
  if (policy.evaluatorKeyId !== trustedEvaluatorKeyId || !sameBytes(evaluatorBytes, expectedBytes)) {
    throw new PrivateResponseCryptoError(
      "This event\u2019s evaluator does not match the evaluator trusted by this Herd release."
    );
  }
  if (evaluatorBytes[0] !== 4) {
    throw new PrivateResponseCryptoError(
      "The trusted evaluator key is not an uncompressed P-256 key."
    );
  }
  const policyHash = strictBase64UrlBytes(
    policy.policyHash,
    POLICY_HASH_BYTES2,
    "policyHash"
  );
  if (typeof policy.canonicalDocument !== "string" || !policy.canonicalDocument) {
    throw new PrivateResponseCryptoError("The frozen event policy is missing.");
  }
  const computedPolicyHash = new Uint8Array(
    await cryptoApi2().subtle.digest(
      "SHA-256",
      toArrayBuffer(textEncoder.encode(policy.canonicalDocument))
    )
  );
  if (!sameBytes(policyHash, computedPolicyHash)) {
    throw new PrivateResponseCryptoError("The frozen event policy hash is invalid.");
  }
  if (!serverVerifiedTrust) {
    const policySigningPin = configuredPolicySigningPin();
    if (!policySigningPin) {
      throw new PrivateResponseCryptoError(
        "Private responses are unavailable because this Herd release has no policy-signing trust pin."
      );
    }
    try {
      await verifyEventPolicyCertification(policy, policySigningPin);
    } catch {
      throw new PrivateResponseCryptoError(
        "The frozen event policy is not certified by this Herd release."
      );
    }
  }
  let document;
  try {
    const parsed = JSON.parse(policy.canonicalDocument);
    document = requireRecord(parsed, "Frozen event policy");
    if (JSON.stringify(parsed) !== policy.canonicalDocument) {
      throw new PrivateResponseCryptoError(
        "The frozen event policy document is not canonical JSON."
      );
    }
  } catch (error) {
    if (error instanceof PrivateResponseCryptoError) throw error;
    throw new PrivateResponseCryptoError("The frozen event policy could not be decoded.");
  }
  const event = requireRecord(document.event, "Frozen event policy event");
  const eventId = normalizeUuid(event.id, "Frozen event policy event ID");
  if (!Array.isArray(document.members) || document.members.length > MAX_PARTICIPANTS - 1) {
    throw new PrivateResponseCryptoError("The frozen event member list is invalid.");
  }
  const inviteeIds = document.members.map((rawMember, index) => {
    const member = requireRecord(rawMember, `Frozen event policy members[${index}]`);
    return normalizeUuid(member.id, `Frozen event policy members[${index}].id`);
  });
  if (new Set(inviteeIds).size !== inviteeIds.length) {
    throw new PrivateResponseCryptoError("The frozen event contains duplicate members.");
  }
  const limits = requireRecord(document.limits, "Frozen event policy limits");
  const maximumParticipants = boundedInteger(
    limits.maximumParticipants,
    "Frozen event participant maximum",
    2,
    MAX_PARTICIPANTS
  );
  if (inviteeIds.length + 1 !== maximumParticipants) {
    throw new PrivateResponseCryptoError(
      "The frozen event participant maximum does not match its member list."
    );
  }
  const hostRules = requireRecord(document.hostRules, "Frozen event policy host rules");
  const hostMinimumParticipants = boundedInteger(
    hostRules.minimumParticipants,
    "Frozen host minimum",
    2,
    maximumParticipants
  );
  const documentEvaluator = requireRecord(
    document.evaluator,
    "Frozen event policy evaluator"
  );
  let documentEvaluatorPublicKey;
  try {
    documentEvaluatorPublicKey = strictBase64UrlBytes(
      normalizeEvaluatorPublicKey(documentEvaluator.publicKey),
      EVALUATOR_PUBLIC_KEY_BYTES2,
      "Frozen event policy evaluator public key"
    );
  } catch {
    throw new PrivateResponseCryptoError(
      "The frozen event policy evaluator key is malformed."
    );
  }
  if (document.protocolVersion !== policy.protocolVersion || document.cipherSuite !== policy.cipherSuite || limits.paddedPlaintextBytes !== policy.paddedPlaintextBytes || documentEvaluator.keyId !== policy.evaluatorKeyId || documentEvaluator.measurement !== policy.evaluatorMeasurement || document.releaseId !== policy.releaseId || !sameBytes(documentEvaluatorPublicKey, evaluatorBytes)) {
    throw new PrivateResponseCryptoError(
      "The frozen event policy document does not match its trusted descriptor."
    );
  }
  return {
    evaluatorKeyId: policy.evaluatorKeyId,
    evaluatorPublicKey: evaluatorBytes,
    eventId,
    inviteeIds,
    hostMinimumParticipants,
    maximumParticipants
  };
}
function serializePaddedDraft(draft) {
  const canonical = {
    protocolVersion: draft.protocolVersion,
    eventId: draft.eventId,
    inviteeId: draft.inviteeId,
    policyHash: draft.policyHash,
    envelopeId: draft.envelopeId,
    accountKeyEpochId: draft.accountKeyEpochId,
    revision: draft.revision,
    response: draft.response,
    minimumParticipants: draft.minimumParticipants,
    requiredGroups: draft.requiredGroups.map((group) => ({
      id: group.id,
      memberIDs: group.memberIDs
    })),
    nonce: draft.nonce
  };
  const encoded = textEncoder.encode(JSON.stringify(canonical));
  if (encoded.length > PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES - 2) {
    throw new PrivateResponseCryptoError("The private response is too large.");
  }
  const framed = randomBytes(PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES);
  new DataView(framed.buffer).setUint16(0, encoded.length, false);
  framed.set(encoded, 2);
  return framed;
}
async function importAesKey(rawKey, usages) {
  if (rawKey.length !== RESPONSE_KEY_BYTES) {
    throw new PrivateResponseCryptoError("A private-response key has the wrong size.");
  }
  return cryptoApi2().subtle.importKey(
    "raw",
    toArrayBuffer(rawKey),
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}
async function deriveHkdfAesKey(inputKey, salt, info, usages) {
  const baseKey = await cryptoApi2().subtle.importKey(
    "raw",
    toArrayBuffer(inputKey),
    "HKDF",
    false,
    ["deriveKey"]
  );
  return cryptoApi2().subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(info)
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}
async function deriveHkdfBytes(inputKey, salt, info, length) {
  const baseKey = await cryptoApi2().subtle.importKey(
    "raw",
    toArrayBuffer(inputKey),
    "HKDF",
    false,
    ["deriveBits"]
  );
  return new Uint8Array(
    await cryptoApi2().subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(info)
      },
      baseKey,
      length * 8
    )
  );
}
async function deriveResponseSigningKey(accountRootSecret, envelope) {
  const seed = await deriveHkdfBytes(
    accountRootSecret,
    strictBase64UrlBytes(envelope.policyHash, POLICY_HASH_BYTES2, "policyHash"),
    concatenateBytes(
      textEncoder.encode(PRIVATE_RESPONSE_SIGNING_DERIVATION_LABEL),
      new Uint8Array([0]),
      uuidToBytes(envelope.eventId),
      uuidToBytes(envelope.inviteeId)
    ),
    RESPONSE_KEY_BYTES
  );
  const pkcs8 = concatenateBytes(ED25519_PKCS8_SEED_PREFIX, seed);
  try {
    const temporaryPrivateKey = await cryptoApi2().subtle.importKey(
      "pkcs8",
      toArrayBuffer(pkcs8),
      { name: "Ed25519" },
      true,
      ["sign"]
    );
    const jwk = await cryptoApi2().subtle.exportKey("jwk", temporaryPrivateKey);
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
      throw new PrivateResponseCryptoError(
        "The browser produced an invalid response-signing key."
      );
    }
    const publicKey = strictBase64UrlBytes(
      jwk.x,
      PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES,
      "responseSigningPublicKey"
    );
    const privateKey = await cryptoApi2().subtle.importKey(
      "pkcs8",
      toArrayBuffer(pkcs8),
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    return { privateKey, publicKey };
  } catch (error) {
    if (error instanceof PrivateResponseCryptoError) throw error;
    throw new PrivateResponseCryptoError(
      "This browser cannot create the required response-authentication signature."
    );
  } finally {
    seed.fill(0);
    pkcs8.fill(0);
  }
}
async function aesGcmSeal(key, plaintext, additionalData) {
  const iv = randomBytes(AES_GCM_NONCE_BYTES);
  const ciphertextAndTag = new Uint8Array(
    await cryptoApi2().subtle.encrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        additionalData: toArrayBuffer(additionalData),
        tagLength: AES_GCM_TAG_BITS
      },
      key,
      toArrayBuffer(plaintext)
    )
  );
  return concatenateBytes(iv, ciphertextAndTag);
}
async function sealPrivateResponse(input, serverVerifiedTrust) {
  if (input.accountRootSecret.length !== RESPONSE_KEY_BYTES) {
    throw new PrivateResponseCryptoError("The account root secret has the wrong size.");
  }
  const trustedEvaluator = await assertTrustedPolicy(input.policy, serverVerifiedTrust);
  const envelopeId = randomUuid();
  const draft = normalizeDraft(
    {
      protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
      eventId: input.eventId,
      inviteeId: input.inviteeId,
      policyHash: input.policy.policyHash,
      envelopeId,
      accountKeyEpochId: input.accountKeyEpochId,
      revision: input.revision,
      response: input.response,
      minimumParticipants: input.minimumParticipants,
      requiredGroups: input.requiredGroups,
      nonce: bytesToBase64Url(randomBytes(DRAFT_NONCE_BYTES))
    },
    input.allowedInviteeIds,
    trustedEvaluator
  );
  const envelopeBase = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    envelopeId: draft.envelopeId,
    eventId: draft.eventId,
    inviteeId: draft.inviteeId,
    policyHash: draft.policyHash,
    revision: draft.revision,
    accountKeyEpochId: draft.accountKeyEpochId,
    evaluatorKeyId: trustedEvaluator.evaluatorKeyId,
    payloadCiphertext: "",
    userKeyWrap: "",
    evaluatorKeyWrap: ""
  };
  const responseKeyBytes = randomBytes(RESPONSE_KEY_BYTES);
  let paddedPlaintext = null;
  let sharedSecret = null;
  try {
    const responseKey = await importAesKey(responseKeyBytes, ["encrypt"]);
    paddedPlaintext = serializePaddedDraft(draft);
    const payloadFrame = await aesGcmSeal(
      responseKey,
      paddedPlaintext,
      privateResponseAad("payload", envelopeBase)
    );
    const policyHash = strictBase64UrlBytes(
      draft.policyHash,
      POLICY_HASH_BYTES2,
      "policyHash"
    );
    const userKek = await deriveHkdfAesKey(
      input.accountRootSecret,
      policyHash,
      privateResponseAad("user-key-derivation", envelopeBase),
      ["encrypt"]
    );
    const userWrapFrame = await aesGcmSeal(
      userKek,
      responseKeyBytes,
      privateResponseAad("user-key-wrap", envelopeBase)
    );
    const subtle = cryptoApi2().subtle;
    const evaluatorPublicKey2 = await subtle.importKey(
      "raw",
      toArrayBuffer(trustedEvaluator.evaluatorPublicKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const ephemeralKeyPair = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const ephemeralPublicKey = new Uint8Array(
      await subtle.exportKey("raw", ephemeralKeyPair.publicKey)
    );
    if (ephemeralPublicKey.length !== EVALUATOR_PUBLIC_KEY_BYTES2 || ephemeralPublicKey[0] !== 4) {
      throw new PrivateResponseCryptoError(
        "The browser produced an invalid P-256 key."
      );
    }
    sharedSecret = new Uint8Array(
      await subtle.deriveBits(
        { name: "ECDH", public: evaluatorPublicKey2 },
        ephemeralKeyPair.privateKey,
        256
      )
    );
    const evaluatorSalt = randomBytes(EVALUATOR_SALT_BYTES);
    const evaluatorKeyIdBytes = textEncoder.encode(
      trustedEvaluator.evaluatorKeyId
    );
    const evaluatorKek = await deriveHkdfAesKey(
      sharedSecret,
      evaluatorSalt,
      concatenateBytes(
        privateResponseAad("evaluator-key-derivation", envelopeBase),
        evaluatorKeyIdBytes
      ),
      ["encrypt"]
    );
    const evaluatorWrappedResponseKey = await aesGcmSeal(
      evaluatorKek,
      responseKeyBytes,
      concatenateBytes(
        privateResponseAad("evaluator-key-wrap", envelopeBase),
        evaluatorKeyIdBytes,
        ephemeralPublicKey,
        evaluatorSalt
      )
    );
    const evaluatorWrapFrame = concatenateBytes(
      ephemeralPublicKey,
      evaluatorSalt,
      evaluatorWrappedResponseKey
    );
    if (payloadFrame.length !== PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES || userWrapFrame.length !== PRIVATE_RESPONSE_USER_WRAP_BYTES || evaluatorWrapFrame.length !== PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES) {
      throw new PrivateResponseCryptoError(
        "The browser produced an invalid envelope size."
      );
    }
    const derivedSigningKey = await deriveResponseSigningKey(
      input.accountRootSecret,
      envelopeBase
    );
    const unsignedEnvelope = normalizePrivateResponseUnsignedEnvelope({
      ...envelopeBase,
      payloadCiphertext: bytesToBase64Url(payloadFrame),
      userKeyWrap: bytesToBase64Url(userWrapFrame),
      evaluatorKeyWrap: bytesToBase64Url(evaluatorWrapFrame),
      responseSigningPublicKey: bytesToBase64Url(derivedSigningKey.publicKey)
    });
    const ciphertextHash = await privateResponseEnvelopeHash(unsignedEnvelope);
    const signature = new Uint8Array(
      await cryptoApi2().subtle.sign(
        { name: "Ed25519" },
        derivedSigningKey.privateKey,
        toArrayBuffer(
          privateResponseAuthorizationBytes(unsignedEnvelope, ciphertextHash)
        )
      )
    );
    const envelope = normalizePrivateResponseEnvelope({
      ...unsignedEnvelope,
      responseSignature: bytesToBase64Url(signature)
    });
    signature.fill(0);
    return { envelope, draft };
  } finally {
    responseKeyBytes.fill(0);
    paddedPlaintext?.fill(0);
    sharedSecret?.fill(0);
  }
}
async function privateResponseEnvelopeHash(envelope) {
  const digest2 = await cryptoApi2().subtle.digest(
    "SHA-256",
    toArrayBuffer(textEncoder.encode(canonicalEnvelopeJson(envelope)))
  );
  return bytesToBase64Url(new Uint8Array(digest2));
}

// invitee-web/lib/backend/http.ts
var ApiError = class extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
};

// invitee-web/lib/backend/config.ts
function boundedInteger2(value, fallback, minimum, maximum) {
  if (value === void 0 || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ApiError(500, "server_misconfigured", "Authentication timing is misconfigured.");
  }
  return parsed;
}
function required(value, name) {
  if (!value) {
    throw new ApiError(500, "server_misconfigured", `${name} is not configured.`);
  }
  return value;
}
function requiredBounded(value, name, maximum) {
  const result = required(value, name).trim();
  if (!result || result.length > maximum || /[\u0000-\u001f\u007f]/u.test(result)) {
    throw new ApiError(500, "server_misconfigured", `${name} is invalid.`);
  }
  return result;
}
function evaluatorKeyId(value) {
  const result = requiredBounded(value, "HERD_EVALUATOR_KEY_ID", 120);
  if (!/^[A-Za-z0-9._-]+$/u.test(result)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_KEY_ID must be a release-scoped identifier."
    );
  }
  return result;
}
function evaluatorPublicKey(value) {
  try {
    const normalized = normalizeEvaluatorPublicKey(
      requiredBounded(value, "HERD_EVALUATOR_PUBLIC_KEY", 200)
    );
    const bytes = base64UrlToBytes(normalized);
    if (bytes[0] !== 4 || bytesToBase64Url(bytes) !== normalized) {
      throw new TypeError("Invalid X9.63 point encoding.");
    }
    return normalized;
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_PUBLIC_KEY must be an unpadded base64url P-256 X9.63 key."
    );
  }
}
function p256SigningKeyId(value, bindingName) {
  const result = requiredBounded(
    value,
    bindingName,
    120
  );
  if (!/^[A-Za-z0-9._-]+$/u.test(result)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      `${bindingName} must be a release-scoped identifier.`
    );
  }
  return result;
}
function p256SigningPublicKey(value, bindingName) {
  try {
    const normalized = normalizeEvaluatorPublicKey(
      requiredBounded(
        value,
        bindingName,
        200
      )
    );
    const bytes = base64UrlToBytes(normalized);
    if (bytes[0] !== 4 || bytesToBase64Url(bytes) !== normalized) {
      throw new TypeError("Invalid X9.63 point encoding.");
    }
    return normalized;
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      `${bindingName} must be an unpadded base64url P-256 X9.63 key.`
    );
  }
}
function getDeploymentProfile(bindings) {
  const value = bindings.HERD_DEPLOYMENT_PROFILE?.trim().toLowerCase();
  if (value === "production" || !value) return "production";
  if (value === "test") return "test";
  if (value) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_DEPLOYMENT_PROFILE must be production or test."
    );
  }
  return "production";
}
function optionalBoolean(value, name) {
  if (value === void 0 || value.trim() === "") return false;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  throw new ApiError(500, "server_misconfigured", `${name} must be true or false.`);
}
function testAccountAccessConfig(bindings) {
  const enabled = optionalBoolean(
    bindings.HERD_TEST_ACCOUNT_ACCESS_ENABLED,
    "HERD_TEST_ACCOUNT_ACCESS_ENABLED"
  );
  if (!enabled) return { enabled: false, generation: null };
  const generation = requiredBounded(
    bindings.HERD_TEST_ACCOUNT_ACCESS_GENERATION,
    "HERD_TEST_ACCOUNT_ACCESS_GENERATION",
    120
  );
  if (generation.length < 16 || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(generation)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_TEST_ACCOUNT_ACCESS_GENERATION must be a unique identifier of at least 16 safe characters."
    );
  }
  return { enabled: true, generation };
}
function getEvaluatorServiceConfig(bindings) {
  const rawUrl = requiredBounded(bindings.HERD_EVALUATOR_URL, "HERD_EVALUATOR_URL", 2048);
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_URL must be a valid HTTPS endpoint."
    );
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.origin === "null") {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_URL must be a valid HTTPS endpoint."
    );
  }
  const token = requiredBounded(
    bindings.HERD_EVALUATOR_TOKEN,
    "HERD_EVALUATOR_TOKEN",
    512
  );
  if (token.length < 32) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_TOKEN must contain at least 32 characters."
    );
  }
  const sitesBypassToken = bindings.HERD_EVALUATOR_SITES_BYPASS_TOKEN ? requiredBounded(
    bindings.HERD_EVALUATOR_SITES_BYPASS_TOKEN,
    "HERD_EVALUATOR_SITES_BYPASS_TOKEN",
    512
  ) : null;
  if (sitesBypassToken && sitesBypassToken.length < 32) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_SITES_BYPASS_TOKEN must contain at least 32 characters."
    );
  }
  return { url: url.toString(), token, sitesBypassToken };
}
function getEvaluatorTransport(bindings) {
  const value = bindings.HERD_EVALUATOR_TRANSPORT?.trim().toLowerCase();
  const profile = getDeploymentProfile(bindings);
  if (!value) return profile === "production" ? "client_relay" : "direct";
  if (value === "direct") {
    if (profile === "production") {
      throw new ApiError(
        500,
        "server_misconfigured",
        "Production evaluation must use the signed client-relay transport."
      );
    }
    return "direct";
  }
  if (value === "client_relay") return "client_relay";
  throw new ApiError(
    500,
    "server_misconfigured",
    "HERD_EVALUATOR_TRANSPORT must be direct or client_relay."
  );
}
function getEvaluatorRelayConfig(bindings) {
  if (getEvaluatorTransport(bindings) !== "client_relay") {
    throw new ApiError(
      409,
      "evaluation_relay_disabled",
      "Client-relay evaluation is not enabled."
    );
  }
  const service = getEvaluatorServiceConfig(bindings);
  const url = new URL(service.url);
  if (url.pathname !== "/api/v1/relay/" || url.search || url.hash || url.username || url.password) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Client-relay evaluation must use the exact HTTPS /api/v1/relay/ endpoint."
    );
  }
  const resultSigning = getEvaluatorResultSigningConfig(bindings);
  return {
    ...service,
    ...resultSigning,
    transport: "client_relay",
    evaluatorHost: url.origin,
    evaluatorKeyId: evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID),
    evaluatorPublicKey: evaluatorPublicKey(bindings.HERD_EVALUATOR_PUBLIC_KEY)
  };
}
function getEvaluatorResultSigningConfig(bindings) {
  const resultSigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
    "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID"
  );
  const resultSigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY"
  );
  const evaluatorEncryptionKeyId = evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID);
  const evaluatorEncryptionPublicKey = evaluatorPublicKey(
    bindings.HERD_EVALUATOR_PUBLIC_KEY
  );
  if (resultSigningKeyId === evaluatorEncryptionKeyId || resultSigningPublicKey === evaluatorEncryptionPublicKey) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator result signing key must be distinct from its response decryption key."
    );
  }
  return {
    resultSigningKeyId,
    resultSigningPublicKey
  };
}
function getEvaluatorTrustSigningConfig(bindings) {
  const values = [
    bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY
  ];
  const configured = values.filter((value) => Boolean(value?.trim())).length;
  if (configured === 0 && getDeploymentProfile(bindings) === "test") return null;
  if (configured !== values.length) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Evaluator policy and transparency signing pins must be configured together."
    );
  }
  const service = getEvaluatorServiceConfig(bindings);
  const policySigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
    "HERD_EVALUATOR_POLICY_SIGNING_KEY_ID"
  );
  const policySigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY"
  );
  const transparencySigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
    "HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID"
  );
  const transparencySigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY"
  );
  const encryptionKeyId = evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID);
  const encryptionPublicKey = evaluatorPublicKey(bindings.HERD_EVALUATOR_PUBLIC_KEY);
  const resultSigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
    "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID"
  );
  const resultSigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY"
  );
  const keyIds = [
    encryptionKeyId,
    resultSigningKeyId,
    policySigningKeyId,
    transparencySigningKeyId
  ];
  const publicKeys = [
    encryptionPublicKey,
    resultSigningPublicKey,
    policySigningPublicKey,
    transparencySigningPublicKey
  ];
  if (new Set(keyIds).size !== keyIds.length || new Set(publicKeys).size !== publicKeys.length) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Every evaluator purpose must use a distinct release-scoped key pair."
    );
  }
  return {
    ...service,
    policySigningKeyId,
    policySigningPublicKey,
    transparencySigningKeyId,
    transparencySigningPublicKey
  };
}
function twilioSid(value, name, prefix) {
  const result = requiredBounded(value, name, 34);
  if (!new RegExp(`^${prefix}[0-9a-fA-F]{32}$`, "u").test(result)) {
    throw new ApiError(500, "server_misconfigured", `${name} is invalid.`);
  }
  return result;
}
function getInvitationDeliveryConfig(bindings) {
  const activationValues = [
    bindings.HERD_PUBLIC_APP_URL,
    bindings.TWILIO_ACCOUNT_SID,
    bindings.TWILIO_MESSAGING_SERVICE_SID
  ];
  if (!activationValues.some((value) => Boolean(value?.trim()))) return null;
  const rawPublicAppUrl = requiredBounded(
    bindings.HERD_PUBLIC_APP_URL,
    "HERD_PUBLIC_APP_URL",
    2048
  );
  let publicAppUrl;
  try {
    publicAppUrl = new URL(rawPublicAppUrl);
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_PUBLIC_APP_URL must be a valid HTTPS URL."
    );
  }
  if (publicAppUrl.protocol !== "https:" || publicAppUrl.username || publicAppUrl.password || publicAppUrl.search || publicAppUrl.hash || publicAppUrl.origin === "null") {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_PUBLIC_APP_URL must be a valid HTTPS URL without credentials, query, or fragment."
    );
  }
  publicAppUrl.pathname = publicAppUrl.pathname.replace(/\/+$/u, "") || "/";
  return {
    publicAppUrl: publicAppUrl.toString().replace(/\/$/u, ""),
    twilio: {
      accountSid: twilioSid(bindings.TWILIO_ACCOUNT_SID, "TWILIO_ACCOUNT_SID", "AC"),
      apiKeySid: twilioSid(bindings.TWILIO_API_KEY_SID, "TWILIO_API_KEY_SID", "SK"),
      apiKeySecret: requiredBounded(
        bindings.TWILIO_API_KEY_SECRET,
        "TWILIO_API_KEY_SECRET",
        512
      ),
      messagingServiceSid: twilioSid(
        bindings.TWILIO_MESSAGING_SERVICE_SID,
        "TWILIO_MESSAGING_SERVICE_SID",
        "MG"
      )
    }
  };
}
function getAuthConfig(bindings) {
  const pepper = required(bindings.HERD_AUTH_PEPPER, "HERD_AUTH_PEPPER");
  if (pepper.length < 32) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_AUTH_PEPPER must contain at least 32 characters."
    );
  }
  const testAccountAccess = testAccountAccessConfig(bindings);
  const twilioValues = [
    bindings.TWILIO_API_KEY_SID,
    bindings.TWILIO_API_KEY_SECRET,
    bindings.TWILIO_VERIFY_SERVICE_SID
  ];
  const hasAnyTwilioValue = twilioValues.some((value) => Boolean(value?.trim()));
  const hasAllTwilioValues = twilioValues.every((value) => Boolean(value?.trim()));
  if (hasAnyTwilioValue && !hasAllTwilioValues) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Phone verification credentials are incomplete."
    );
  }
  const twilio = hasAllTwilioValues ? {
    apiKeySid: bindings.TWILIO_API_KEY_SID.trim(),
    apiKeySecret: bindings.TWILIO_API_KEY_SECRET.trim(),
    verifyServiceSid: bindings.TWILIO_VERIFY_SERVICE_SID.trim()
  } : null;
  const privateResponseValues = [
    bindings.HERD_EVALUATOR_KEY_ID,
    bindings.HERD_EVALUATOR_PUBLIC_KEY,
    bindings.HERD_EVALUATOR_MEASUREMENT,
    bindings.HERD_RELEASE_ID
  ];
  const hasAnyPrivateResponseValue = privateResponseValues.some((value) => Boolean(value?.trim()));
  const hasAllPrivateResponseValues = privateResponseValues.every((value) => Boolean(value?.trim()));
  if (hasAnyPrivateResponseValue && !hasAllPrivateResponseValues) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Private-response credentials are incomplete."
    );
  }
  const privateResponse = hasAllPrivateResponseValues ? {
    evaluatorKeyId: evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID),
    evaluatorPublicKey: evaluatorPublicKey(bindings.HERD_EVALUATOR_PUBLIC_KEY),
    evaluatorMeasurement: requiredBounded(
      bindings.HERD_EVALUATOR_MEASUREMENT,
      "HERD_EVALUATOR_MEASUREMENT",
      500
    ),
    releaseId: requiredBounded(bindings.HERD_RELEASE_ID, "HERD_RELEASE_ID", 200)
  } : null;
  return {
    pepper,
    testAccountAccessEnabled: testAccountAccess.enabled,
    testAccountAccessGeneration: testAccountAccess.generation,
    challengeTtlSeconds: boundedInteger2(
      bindings.HERD_CHALLENGE_TTL_SECONDS,
      600,
      120,
      1800
    ),
    resendSeconds: boundedInteger2(bindings.HERD_RESEND_SECONDS, 60, 30, 600),
    maxCodeAttempts: boundedInteger2(bindings.HERD_MAX_CODE_ATTEMPTS, 5, 3, 10),
    phoneRequestsPerHour: boundedInteger2(
      bindings.HERD_PHONE_REQUESTS_PER_HOUR,
      5,
      2,
      20
    ),
    ipRequestsPerHour: boundedInteger2(
      bindings.HERD_IP_REQUESTS_PER_HOUR,
      30,
      5,
      200
    ),
    sessionTtlSeconds: boundedInteger2(
      bindings.HERD_SESSION_TTL_SECONDS,
      2592e3,
      3600,
      7776e3
    ),
    privateResponse,
    twilio
  };
}

// invitee-web/lib/backend/crypto.ts
var encoder = new TextEncoder();
function bytesToBase64Url2(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomUuid2() {
  return crypto.randomUUID();
}
async function pepperedHash(pepper, purpose, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${purpose}\0${value}`)
  );
  return bytesToBase64Url2(new Uint8Array(signature));
}

// invitee-web/lib/backend/ballot-identifiers.ts
function ballotKey(bindings) {
  const configured = bindings.HERD_BALLOT_PSEUDONYM_KEY?.trim() ?? "";
  if (configured.length >= 32) return configured;
  if (bindings.HERD_DEPLOYMENT_PROFILE === "test") {
    const testKey = bindings.HERD_AUTH_PEPPER?.trim() ?? "";
    if (testKey.length >= 32) return testKey;
  }
  throw new ApiError(
    500,
    "server_misconfigured",
    "The ballot pseudonym key is not configured."
  );
}
async function deriveBallotId(bindings, eventId, inviteeId) {
  return pepperedHash(ballotKey(bindings), "HERD-BALLOT-V2", `${eventId}:${inviteeId}`);
}
async function deriveBallotMemberId(bindings, eventId, inviteeId) {
  return pepperedHash(ballotKey(bindings), "HERD-MEMBER-V2", `${eventId}:${inviteeId}`);
}

// invitee-web/lib/backend/evaluator-trust.ts
var TransparencyLateMissingEntryError = class extends ApiError {
  constructor(proof) {
    super(
      409,
      "response_transparency_late_missing_entry",
      "The encrypted response reached the independent log after its authority deadline."
    );
    this.name = "TransparencyLateMissingEntryError";
    this.proof = proof;
  }
};
var MAXIMUM_SIGNER_RESPONSE_BYTES = 16 * 1024;
var IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/u;
function ownedArrayBuffer2(value) {
  return Uint8Array.from(value).buffer;
}
function exactRecord(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("The evaluator signer returned an invalid object.");
  }
  const record = value;
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError("The evaluator signer returned unsupported fields.");
  }
  return record;
}
function canonicalHash(value) {
  if (typeof value !== "string") {
    throw new TypeError("The evaluator reconciliation hash is invalid.");
  }
  const decoded = base64UrlToBytes(value);
  if (decoded.length !== PRIVATE_RESPONSE_HASH_BYTES || bytesToBase64Url(decoded) !== value) {
    throw new TypeError("The evaluator reconciliation hash is invalid.");
  }
  return value;
}
function canonicalTimestamp(value) {
  if (typeof value !== "string") {
    throw new TypeError("The evaluator reconciliation time is invalid.");
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new TypeError("The evaluator reconciliation time is invalid.");
  }
  return value;
}
async function lateMissingEntryProof(value, config) {
  const outer = exactRecord(value, ["error"]);
  const error = exactRecord(outer.error, ["code", "proof"]);
  if (error.code !== "transparency_late_missing_entry") {
    throw new TypeError("The evaluator reconciliation code is invalid.");
  }
  const proof = exactRecord(error.proof, [
    "canonicalPayload",
    "domain",
    "payloadHash",
    "signature",
    "signingKeyId"
  ]);
  if (proof.domain !== PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN || proof.signingKeyId !== config.transparencySigningKeyId || typeof proof.canonicalPayload !== "string" || proof.canonicalPayload.length < 2 || proof.canonicalPayload.length > MAXIMUM_SIGNER_RESPONSE_BYTES || typeof proof.signature !== "string") {
    throw new TypeError("The evaluator reconciliation proof is invalid.");
  }
  const payload = exactRecord(JSON.parse(proof.canonicalPayload), [
    "protocolVersion",
    "logId",
    "rejectedLogIndex",
    "rejectedEntryHash",
    "authorityTreeSize",
    "authorityHeadEntryHash",
    "generatedAt",
    "signingKeyId"
  ]);
  if (payload.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || payload.logId !== PRIVATE_RESPONSE_LOG_ID || !Number.isSafeInteger(payload.rejectedLogIndex) || payload.rejectedLogIndex < 1 || !Number.isSafeInteger(payload.authorityTreeSize) || payload.authorityTreeSize < 0 || payload.authorityTreeSize + 1 !== payload.rejectedLogIndex || payload.signingKeyId !== config.transparencySigningKeyId) {
    throw new TypeError("The evaluator reconciliation payload is invalid.");
  }
  const normalized = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: PRIVATE_RESPONSE_LOG_ID,
    rejectedLogIndex: payload.rejectedLogIndex,
    rejectedEntryHash: canonicalHash(payload.rejectedEntryHash),
    authorityTreeSize: payload.authorityTreeSize,
    authorityHeadEntryHash: canonicalHash(payload.authorityHeadEntryHash),
    generatedAt: canonicalTimestamp(payload.generatedAt),
    signingKeyId: config.transparencySigningKeyId
  };
  const payloadHash = await sha256Base64Url(proof.canonicalPayload);
  if (JSON.stringify(normalized) !== proof.canonicalPayload || proof.payloadHash !== payloadHash || !await verifyP256Signature(
    config.transparencySigningPublicKey,
    PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN,
    proof.canonicalPayload,
    proof.signature
  )) {
    throw new TypeError("The evaluator reconciliation signature is invalid.");
  }
  return {
    ...normalized,
    canonicalPayload: proof.canonicalPayload,
    signature: proof.signature
  };
}
async function sha256Base64Url(value) {
  const digest2 = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest2));
}
async function verifyP256Signature(publicKey, domain, canonicalPayload, signature) {
  const publicKeyBytes = base64UrlToBytes(publicKey);
  const signatureBytes = base64UrlToBytes(signature);
  if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 4 || signatureBytes.length !== PRIVATE_RESPONSE_SIGNATURE_BYTES || bytesToBase64Url(signatureBytes) !== signature) {
    return false;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer2(publicKeyBytes),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    ownedArrayBuffer2(signatureBytes),
    ownedArrayBuffer2(domainSeparatedUtf8(domain, canonicalPayload))
  );
}
function signerHeaders(config) {
  const headers = new Headers({
    authorization: `Bearer ${config.token}`,
    "content-type": "application/json"
  });
  if (config.sitesBypassToken) {
    headers.set("OAI-Sites-Authorization", `Bearer ${config.sitesBypassToken}`);
  }
  return headers;
}
async function signerJson(response) {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > MAXIMUM_SIGNER_RESPONSE_BYTES) {
    throw new TypeError("The evaluator signer response is too large.");
  }
  const text = await response.text();
  if (text.length > MAXIMUM_SIGNER_RESPONSE_BYTES) {
    throw new TypeError("The evaluator signer response is too large.");
  }
  return JSON.parse(text);
}
async function callTransparencyAuthority(config, canonicalReceiptPayload) {
  let response;
  try {
    response = await fetch(new URL("/api/v1/sign/transparency", config.url), {
      method: "POST",
      headers: signerHeaders(config),
      body: JSON.stringify({
        protocolVersion: 1,
        kind: "append",
        canonicalReceiptPayload
      }),
      redirect: "manual"
    });
  } catch (error) {
    console.error("evaluator_transparency_request_failed", {
      reason: error instanceof Error ? error.name : "unknown"
    });
    throw new ApiError(
      503,
      "evaluator_trust_unavailable",
      "The confidential evaluator could not certify this operation."
    );
  }
  if (!response.ok) {
    console.error("evaluator_transparency_certification_rejected", {
      status: response.status
    });
    if (response.status === 409) {
      let value;
      try {
        value = await signerJson(response);
        const error = exactRecord(value, ["error"]);
        if (!error.error || typeof error.error !== "object" || Array.isArray(error.error)) {
          throw new TypeError("The evaluator conflict response is invalid.");
        }
        const errorCode = error.error.code;
        if (errorCode === "transparency_late_missing_entry") {
          throw new TransparencyLateMissingEntryError(
            await lateMissingEntryProof(value, config)
          );
        }
        const details = exactRecord(error.error, ["code"]);
        if (details.code !== "transparency_conflict") {
          throw new TypeError("The evaluator conflict response is invalid.");
        }
      } catch (error) {
        if (error instanceof TransparencyLateMissingEntryError) throw error;
        throw new ApiError(
          502,
          "invalid_evaluator_trust_proof",
          "The confidential evaluator returned an invalid reconciliation proof."
        );
      }
      throw new ApiError(
        409,
        "response_transparency_conflict",
        "The encrypted response conflicts with the independently committed response log."
      );
    }
    throw new ApiError(
      503,
      "evaluator_trust_unavailable",
      "The confidential evaluator could not certify this operation."
    );
  }
  try {
    const value = exactRecord(await signerJson(response), [
      "protocolVersion",
      "kind",
      "signingKeyId",
      "receipt",
      "logHead"
    ]);
    const receipt = exactRecord(value.receipt, [
      "domain",
      "payloadHash",
      "signature"
    ]);
    const logHead = exactRecord(value.logHead, [
      "canonicalPayload",
      "domain",
      "payloadHash",
      "signature"
    ]);
    const receiptPayloadHash = await sha256Base64Url(canonicalReceiptPayload);
    if (value.protocolVersion !== 1 || value.kind !== "append" || value.signingKeyId !== config.transparencySigningKeyId || typeof value.signingKeyId !== "string" || !IDENTIFIER_PATTERN.test(value.signingKeyId) || receipt.domain !== PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN || receipt.payloadHash !== receiptPayloadHash || typeof receipt.signature !== "string" || typeof logHead.canonicalPayload !== "string" || logHead.canonicalPayload.length < 2 || logHead.canonicalPayload.length > MAXIMUM_SIGNER_RESPONSE_BYTES || logHead.domain !== PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN || typeof logHead.signature !== "string") {
      throw new TypeError("The evaluator transparency proof is invalid.");
    }
    const headPayloadHash = await sha256Base64Url(logHead.canonicalPayload);
    if (logHead.payloadHash !== headPayloadHash || !await verifyP256Signature(
      config.transparencySigningPublicKey,
      PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
      canonicalReceiptPayload,
      receipt.signature
    ) || !await verifyP256Signature(
      config.transparencySigningPublicKey,
      PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
      logHead.canonicalPayload,
      logHead.signature
    )) {
      throw new TypeError("The evaluator transparency signature is invalid.");
    }
    return {
      signingKeyId: value.signingKeyId,
      receipt: {
        payloadHash: receiptPayloadHash,
        signature: receipt.signature
      },
      logHead: {
        canonicalPayload: logHead.canonicalPayload,
        payloadHash: headPayloadHash,
        signature: logHead.signature
      }
    };
  } catch {
    throw new ApiError(
      502,
      "invalid_evaluator_trust_proof",
      "The confidential evaluator returned an invalid certification."
    );
  }
}
async function appendTransparencyEntry(bindings, canonicalReceiptPayload) {
  const config = getEvaluatorTrustSigningConfig(bindings);
  return config ? callTransparencyAuthority(config, canonicalReceiptPayload) : null;
}
async function verifyStoredEventPolicyCertification(bindings, policy) {
  const config = getEvaluatorTrustSigningConfig(bindings);
  if (!config) return true;
  return Boolean(
    policy.policySigningKeyId === config.policySigningKeyId && policy.policySignature && await verifyP256Signature(
      config.policySigningPublicKey,
      PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
      policy.canonicalDocument,
      policy.policySignature
    )
  );
}

// invitee-web/lib/backend/response-envelopes.ts
var RESPONSE_ENVELOPE_SELECT = `SELECT
  id,
  event_id AS eventId,
  invitee_id AS inviteeId,
  policy_hash AS policyHash,
  protocol_version AS protocolVersion,
  cipher_suite AS cipherSuite,
  account_key_epoch_id AS accountKeyEpochId,
  evaluator_key_id AS evaluatorKeyId,
  revision,
  payload_ciphertext AS payloadCiphertext,
  user_key_wrap AS userKeyWrap,
  evaluator_key_wrap AS evaluatorKeyWrap,
  response_signing_public_key AS responseSigningPublicKey,
  response_signature AS responseSignature,
  ciphertext_hash AS ciphertextHash,
  created_at AS createdAt,
  updated_at AS updatedAt
FROM response_envelopes`;
function parseResponseEnvelope(row) {
  if (!row) return null;
  try {
    const envelope = normalizePrivateResponseEnvelope({
      protocolVersion: row.protocolVersion,
      cipherSuite: row.cipherSuite,
      envelopeId: row.id,
      eventId: row.eventId,
      inviteeId: row.inviteeId,
      policyHash: row.policyHash,
      revision: row.revision,
      accountKeyEpochId: row.accountKeyEpochId,
      evaluatorKeyId: row.evaluatorKeyId,
      payloadCiphertext: row.payloadCiphertext,
      userKeyWrap: row.userKeyWrap,
      evaluatorKeyWrap: row.evaluatorKeyWrap,
      responseSigningPublicKey: row.responseSigningPublicKey,
      responseSignature: row.responseSignature
    });
    return {
      ...envelope,
      ciphertextHash: row.ciphertextHash,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    };
  } catch {
    return null;
  }
}
function unstoredResponseEnvelope(envelope) {
  const {
    ciphertextHash: _ciphertextHash,
    createdAt: _createdAt,
    updatedAt: _updatedAt,
    ...storedEnvelope
  } = envelope;
  void _ciphertextHash;
  void _createdAt;
  void _updatedAt;
  return storedEnvelope;
}
async function responseEnvelopeHash(envelope) {
  const digest2 = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalEnvelopeJson(envelope))
  );
  return bytesToBase64Url(new Uint8Array(digest2));
}

// invitee-web/lib/backend/response-transparency.ts
var GENESIS_HASH = bytesToBase64Url(
  new Uint8Array(PRIVATE_RESPONSE_HASH_BYTES)
);
var MAXIMUM_PREFIX_CERTIFICATIONS = 64;
var ENTRY_SELECT = `SELECT
  log_index AS logIndex,
  log_id AS logId,
  previous_entry_hash AS previousEntryHash,
  entry_hash AS entryHash,
  envelope_id AS envelopeId,
  canonical_receipt_payload AS canonicalReceiptPayload,
  signing_key_id AS signingKeyId,
  receipt_signature AS receiptSignature,
  created_at AS createdAt,
  signed_at AS signedAt
FROM response_transparency_entries`;
var HEAD_SELECT = `SELECT
  log_index AS logIndex,
  log_id AS logId,
  head_entry_hash AS headEntryHash,
  canonical_payload AS canonicalPayload,
  signing_key_id AS signingKeyId,
  signature,
  generated_at AS generatedAt
FROM response_transparency_heads`;
function corruptLog() {
  throw new ApiError(
    500,
    "response_transparency_corrupt",
    "The encrypted-response transparency log could not be verified."
  );
}
function authorityHead(canonicalPayload, signature) {
  let input;
  try {
    input = JSON.parse(canonicalPayload);
  } catch {
    corruptLog();
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) corruptLog();
  const value = input;
  const actual = Object.keys(value).sort();
  const expected = [
    "protocolVersion",
    "logId",
    "treeSize",
    "headEntryHash",
    "generatedAt",
    "signingKeyId"
  ].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]) || value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || typeof value.logId !== "string" || !Number.isInteger(value.treeSize) || typeof value.headEntryHash !== "string" || typeof value.generatedAt !== "string" || typeof value.signingKeyId !== "string") {
    corruptLog();
  }
  const head = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: value.logId,
    treeSize: value.treeSize,
    headEntryHash: value.headEntryHash,
    generatedAt: value.generatedAt,
    signingKeyId: value.signingKeyId,
    signature
  };
  const { signature: _signature, ...unsigned } = head;
  void _signature;
  if (canonicalPrivateResponseLogHeadPayload(unsigned) !== canonicalPayload) {
    corruptLog();
  }
  return head;
}
async function certifyStoredEntry(db, bindings, entry) {
  let head = await db.prepare(`${HEAD_SELECT} WHERE log_index = ?`).bind(entry.logIndex).first();
  const certification = entry.receiptSignature && entry.signedAt && head ? null : await appendTransparencyEntry(bindings, entry.canonicalReceiptPayload);
  if ((!entry.receiptSignature || !head) && !certification) corruptLog();
  if (certification && certification.signingKeyId !== entry.signingKeyId) {
    corruptLog();
  }
  const receiptSignature = entry.receiptSignature ?? certification.receipt.signature;
  if (certification && entry.receiptSignature && entry.receiptSignature !== certification.receipt.signature) {
    corruptLog();
  }
  const certifiedHead = certification ? authorityHead(
    certification.logHead.canonicalPayload,
    certification.logHead.signature
  ) : null;
  if (certifiedHead && (certifiedHead.logId !== entry.logId || certifiedHead.treeSize !== entry.logIndex || certifiedHead.headEntryHash !== entry.entryHash || certifiedHead.signingKeyId !== entry.signingKeyId)) {
    corruptLog();
  }
  if (!head) {
    if (!certifiedHead || !certification) {
      corruptLog();
    }
    await db.batch([
      db.prepare(
        `UPDATE response_transparency_entries
           SET receipt_signature = COALESCE(receipt_signature, ?),
               signed_at = COALESCE(signed_at, ?)
           WHERE log_index = ? AND canonical_receipt_payload = ?`
      ).bind(
        receiptSignature,
        (/* @__PURE__ */ new Date()).toISOString(),
        entry.logIndex,
        entry.canonicalReceiptPayload
      ),
      db.prepare(
        `INSERT OR IGNORE INTO response_transparency_heads
            (log_index, log_id, head_entry_hash, canonical_payload,
             signing_key_id, signature, generated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        entry.logIndex,
        entry.logId,
        entry.entryHash,
        certification.logHead.canonicalPayload,
        entry.signingKeyId,
        certification.logHead.signature,
        certifiedHead.generatedAt
      )
    ]);
    head = await db.prepare(`${HEAD_SELECT} WHERE log_index = ?`).bind(entry.logIndex).first();
  } else if (!entry.receiptSignature || !entry.signedAt) {
    await db.prepare(
      `UPDATE response_transparency_entries
         SET receipt_signature = COALESCE(receipt_signature, ?),
             signed_at = COALESCE(signed_at, ?)
         WHERE log_index = ?
           AND (receipt_signature IS NULL OR signed_at IS NULL)`
    ).bind(receiptSignature, (/* @__PURE__ */ new Date()).toISOString(), entry.logIndex).run();
  }
  if (!head) corruptLog();
  if (certification && (head.canonicalPayload !== certification.logHead.canonicalPayload || head.signature !== certification.logHead.signature)) {
    corruptLog();
  }
  const canonicalHead = canonicalPrivateResponseLogHeadPayload({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: head.logId,
    treeSize: head.logIndex,
    headEntryHash: head.headEntryHash,
    generatedAt: head.generatedAt,
    signingKeyId: head.signingKeyId
  });
  if (head.logId !== entry.logId || head.headEntryHash !== entry.entryHash || head.signingKeyId !== entry.signingKeyId || head.canonicalPayload !== canonicalHead) {
    corruptLog();
  }
  return { receiptSignature, head };
}
async function abandonUncertifiedSuffix(db, entry, proof) {
  if (proof.logId !== entry.logId || proof.rejectedLogIndex !== entry.logIndex || proof.rejectedEntryHash !== entry.entryHash || proof.authorityTreeSize + 1 !== entry.logIndex || proof.authorityHeadEntryHash !== entry.previousEntryHash || proof.signingKeyId !== entry.signingKeyId) {
    corruptLog();
  }
  if (proof.authorityTreeSize === 0) {
    if (entry.logIndex !== 1 || entry.previousEntryHash !== GENESIS_HASH) {
      corruptLog();
    }
  } else {
    const prefix = await db.prepare(
      `SELECT
           entries.entry_hash AS entryHash,
           entries.receipt_signature AS receiptSignature,
           entries.signed_at AS signedAt,
           heads.head_entry_hash AS headEntryHash,
           heads.log_id AS headLogId,
           heads.signing_key_id AS headSigningKeyId
         FROM response_transparency_entries AS entries
         LEFT JOIN response_transparency_heads AS heads
           ON heads.log_index = entries.log_index
         WHERE entries.log_index = ?`
    ).bind(proof.authorityTreeSize).first();
    if (!prefix?.receiptSignature || !prefix.signedAt || prefix.entryHash !== proof.authorityHeadEntryHash || prefix.headEntryHash !== proof.authorityHeadEntryHash || prefix.headLogId !== entry.logId || prefix.headSigningKeyId !== entry.signingKeyId) {
      corruptLog();
    }
  }
  const deleted = await db.prepare(
    `WITH reconciliation_guard AS MATERIALIZED (
         SELECT 1 AS allowed
         WHERE EXISTS (
           SELECT 1 FROM response_transparency_entries AS rejected_entry
           WHERE rejected_entry.log_index = ?
             AND rejected_entry.entry_hash = ?
             AND rejected_entry.previous_entry_hash = ?
         )
           AND NOT EXISTS (
           SELECT 1
           FROM response_transparency_entries AS protected_entries
           LEFT JOIN response_transparency_heads AS protected_heads
             ON protected_heads.log_index = protected_entries.log_index
           WHERE protected_entries.log_index >= ?
             AND (
               protected_entries.receipt_signature IS NOT NULL OR
               protected_entries.signed_at IS NOT NULL OR
               protected_heads.log_index IS NOT NULL
             )
           )
       )
       DELETE FROM response_transparency_entries
       WHERE log_index >= ?
         AND EXISTS (SELECT 1 FROM reconciliation_guard WHERE allowed = 1)`
  ).bind(
    entry.logIndex,
    entry.entryHash,
    entry.previousEntryHash,
    entry.logIndex,
    entry.logIndex
  ).run();
  const remaining = await db.prepare(
    `SELECT log_index AS logIndex
       FROM response_transparency_entries
       WHERE log_index >= ?
       ORDER BY log_index ASC
       LIMIT 1`
  ).bind(entry.logIndex).first();
  if ((deleted.meta.changes ?? 0) < 1) corruptLog();
  if (remaining) {
    throw new ApiError(
      503,
      "response_transparency_busy",
      "A new encrypted-response receipt was queued while recovery completed. Evaluation will retry."
    );
  }
}
async function certifyOrAbandonLateSuffix(db, bindings, entry) {
  try {
    return await certifyStoredEntry(db, bindings, entry);
  } catch (error) {
    if (!(error instanceof TransparencyLateMissingEntryError)) throw error;
    await abandonUncertifiedSuffix(db, entry, error.proof);
    return null;
  }
}
async function recoverPendingResponseTransparency(db, bindings) {
  const config = getEvaluatorTrustSigningConfig(bindings);
  if (!config) return;
  const pending = await db.prepare(
    `${ENTRY_SELECT}
       WHERE receipt_signature IS NULL OR signed_at IS NULL OR
         NOT EXISTS (
           SELECT 1 FROM response_transparency_heads AS pending_heads
           WHERE pending_heads.log_index = response_transparency_entries.log_index
         )
       ORDER BY log_index ASC
       LIMIT ?`
  ).bind(MAXIMUM_PREFIX_CERTIFICATIONS).all();
  for (const entry of pending.results) {
    if (!await certifyOrAbandonLateSuffix(db, bindings, entry)) break;
  }
  const remaining = await db.prepare(
    `SELECT log_index AS logIndex
       FROM response_transparency_entries
       WHERE receipt_signature IS NULL OR signed_at IS NULL OR
         NOT EXISTS (
           SELECT 1 FROM response_transparency_heads AS pending_heads
           WHERE pending_heads.log_index = response_transparency_entries.log_index
         )
       ORDER BY log_index ASC
       LIMIT 1`
  ).first();
  if (remaining) {
    throw new ApiError(
      503,
      "response_transparency_busy",
      "Encrypted-response receipts are still being finalized. Evaluation will retry."
    );
  }
}

// invitee-web/lib/backend/invite-tokens.ts
var encoder2 = new TextEncoder();
var TOKEN_BYTES = 32;
var TOKEN_STORAGE_VERSION = 1;
var TOKEN_NONCE_BYTES = 12;
var TOKEN_STORAGE_SALT = encoder2.encode("Herd invitation-token storage key v1");
async function storageKey(pepper) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder2.encode(pepper),
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: TOKEN_STORAGE_SALT,
      info: encoder2.encode("AES-256-GCM")
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
function tokenAdditionalData(eventId, inviteeId) {
  return new Uint8Array(
    encoder2.encode(`herd-invite-token\0v1\0${eventId}\0${inviteeId}`)
  );
}
function validateRawToken(value) {
  try {
    const bytes = base64UrlToBytes(value);
    if (bytes.length !== TOKEN_BYTES || bytesToBase64Url(bytes) !== value) {
      throw new TypeError("Unexpected token encoding.");
    }
    return value;
  } catch {
    throw new ApiError(
      500,
      "invite_token_unavailable",
      "The private invitation link could not be prepared."
    );
  }
}
async function openSealedInviteToken(pepper, eventId, inviteeId, stored) {
  if (stored.tokenStorageVersion !== TOKEN_STORAGE_VERSION || !stored.tokenCiphertext || !stored.tokenNonce) {
    throw new ApiError(
      500,
      "invite_token_unavailable",
      "The private invitation link could not be prepared."
    );
  }
  try {
    const nonce = new Uint8Array(base64UrlToBytes(stored.tokenNonce));
    if (nonce.length !== TOKEN_NONCE_BYTES) throw new TypeError("Invalid nonce.");
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: tokenAdditionalData(eventId, inviteeId),
        tagLength: 128
      },
      await storageKey(pepper),
      new Uint8Array(base64UrlToBytes(stored.tokenCiphertext))
    );
    return validateRawToken(new TextDecoder().decode(plaintext));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      500,
      "invite_token_unavailable",
      "The private invitation link could not be prepared."
    );
  }
}

// invitee-web/lib/backend/resolution-notifications.ts
var TWILIO_MESSAGES_ORIGIN = "https://api.twilio.com";
var DISPATCH_TIMEOUT_MILLISECONDS = 1e4;
function eventDateLabel(value) {
  if (!value) return "a date to be announced";
  return `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC"
  }).format(new Date(value))} UTC`;
}
function resolutionMessageBody(event, status, eventUrl) {
  const title = event.title || "Your event";
  return status === "confirmed" ? `The event "${title}" is now confirmed and will happen on ${eventDateLabel(event.eventDate)}. View event information: ${eventUrl}` : `Herd: ${title} is no longer confirmed. Replies can still change.`;
}
async function sendResolutionTransitionNotifications(db, bindings, event, batchHash, status) {
  const previous = await db.prepare(
    `SELECT status
       FROM resolution_notifications
       WHERE event_id = ?
       ORDER BY created_at DESC, id DESC
       LIMIT 1`
  ).bind(event.id).first();
  if (previous?.status === status || !previous && status === "not_confirmed") return;
  const recipients = await db.prepare(
    `SELECT users.phone_number AS phoneNumber,
              NULL AS inviteeId,
              NULL AS tokenCiphertext,
              NULL AS tokenNonce,
              NULL AS tokenStorageVersion
       FROM events
       JOIN users ON users.id = events.host_user_id
       WHERE events.id = ?
       UNION
       SELECT invitees.phone_number AS phoneNumber,
              invitees.id AS inviteeId,
              invitees.token_ciphertext AS tokenCiphertext,
              invitees.token_nonce AS tokenNonce,
              invitees.token_storage_version AS tokenStorageVersion
       FROM invitees
       WHERE invitees.event_id = ?
       ORDER BY phoneNumber ASC`
  ).bind(event.id, event.id).all();
  const config = getInvitationDeliveryConfig(bindings);
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  for (const recipient of recipients.results) {
    const id = randomUuid2();
    const inserted = await db.prepare(
      `INSERT INTO resolution_notifications
          (id, event_id, batch_hash, status, phone_number, delivery_status,
           provider_message_sid, error_code, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
         ON CONFLICT(event_id, batch_hash, phone_number) DO NOTHING`
    ).bind(
      id,
      event.id,
      batchHash,
      status,
      recipient.phoneNumber,
      "dispatching",
      nowIso,
      nowIso
    ).run();
    if ((inserted.meta.changes ?? 0) !== 1) continue;
    if (!config) {
      await db.prepare(
        `UPDATE resolution_notifications
           SET delivery_status = 'failed', error_code = 'messaging_unavailable', updated_at = ?
           WHERE id = ?`
      ).bind((/* @__PURE__ */ new Date()).toISOString(), id).run();
      continue;
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MILLISECONDS);
    try {
      let eventUrl = config.publicAppUrl;
      if (recipient.inviteeId) {
        try {
          const inviteToken = await openSealedInviteToken(
            getAuthConfig(bindings).pepper,
            event.id,
            recipient.inviteeId,
            recipient
          );
          eventUrl = `${config.publicAppUrl}/invite/${encodeURIComponent(inviteToken)}`;
        } catch {
        }
      }
      const response = await fetch(
        `${TWILIO_MESSAGES_ORIGIN}/2010-04-01/Accounts/${encodeURIComponent(config.twilio.accountSid)}/Messages.json`,
        {
          method: "POST",
          headers: {
            Authorization: `Basic ${btoa(`${config.twilio.apiKeySid}:${config.twilio.apiKeySecret}`)}`,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            To: recipient.phoneNumber,
            MessagingServiceSid: config.twilio.messagingServiceSid,
            Body: resolutionMessageBody(event, status, eventUrl)
          }),
          signal: controller.signal
        }
      );
      const payload = await response.json().catch(() => ({}));
      const providerSid = typeof payload.sid === "string" ? payload.sid.slice(0, 80) : null;
      const errorCode = response.ok ? null : typeof payload.code === "string" || typeof payload.code === "number" ? String(payload.code).slice(0, 80) : `http_${response.status}`;
      await db.prepare(
        `UPDATE resolution_notifications
           SET delivery_status = ?, provider_message_sid = ?, error_code = ?, updated_at = ?
           WHERE id = ? AND delivery_status = 'dispatching'`
      ).bind(
        response.ok ? "sent" : response.status >= 500 ? "unknown" : "failed",
        providerSid,
        errorCode,
        (/* @__PURE__ */ new Date()).toISOString(),
        id
      ).run();
    } catch {
      await db.prepare(
        `UPDATE resolution_notifications
           SET delivery_status = 'unknown', error_code = 'request_ambiguous', updated_at = ?
           WHERE id = ? AND delivery_status = 'dispatching'`
      ).bind((/* @__PURE__ */ new Date()).toISOString(), id).run();
    } finally {
      clearTimeout(timeout);
    }
  }
}

// invitee-web/lib/backend/simple-resolutions.ts
function groupsSatisfied(groups, attendingMemberIds) {
  return groups.every(
    (group) => group.memberIDs.some((memberId) => attendingMemberIds.has(memberId))
  );
}
async function digest(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}
async function loadLatestBallots(db, bindings, event) {
  const rows = await db.prepare(
    `SELECT ballot_id AS ballotId,
              response,
              minimum_participants AS minimumParticipants,
              required_groups AS requiredGroups,
              created_at AS createdAt
       FROM ballot_revisions AS ballot
       WHERE event_id = ?
         AND revision = (
           SELECT MAX(candidate.revision)
           FROM ballot_revisions AS candidate
           WHERE candidate.ballot_id = ballot.ballot_id
         )`
  ).bind(event.id).all();
  const rowsByBallotId = new Map(rows.results.map((row) => [row.ballotId, row]));
  const mapped = await Promise.all(event.invitees.map(async ({ id: inviteeId }) => {
    const [ballotId, memberId] = await Promise.all([
      deriveBallotId(bindings, event.id, inviteeId),
      deriveBallotMemberId(bindings, event.id, inviteeId)
    ]);
    const row = rowsByBallotId.get(ballotId);
    if (!row) return null;
    let requiredGroups = [];
    try {
      const parsed = JSON.parse(row.requiredGroups);
      if (Array.isArray(parsed)) {
        requiredGroups = parsed.flatMap((group) => {
          if (!group || typeof group !== "object" || Array.isArray(group)) return [];
          const memberIDs = group.memberIDs;
          return Array.isArray(memberIDs) && memberIDs.every((member) => typeof member === "string") ? [{ memberIDs }] : [];
        });
      }
    } catch {
      return null;
    }
    return {
      inviteeId,
      memberId,
      response: row.response,
      minimumParticipants: row.minimumParticipants,
      requiredGroups,
      createdAt: row.createdAt
    };
  }));
  return mapped.filter((ballot) => ballot !== null);
}
async function persistResolution(db, eventId, inputDigest, resolution, nowIso) {
  const attendingMemberIds = resolution.status === "confirmed" ? JSON.stringify(resolution.attendingMemberIds ?? []) : null;
  const resolvedAt = resolution.status === "pending" ? null : resolution.resolvedAt;
  await db.prepare(
    `INSERT INTO event_resolutions
        (event_id, policy_hash, status, batch_hash, attending_member_ids,
         resolved_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(event_id) DO UPDATE SET
         policy_hash = excluded.policy_hash,
         status = CASE
           WHEN event_resolutions.status = 'confirmed' THEN event_resolutions.status
           ELSE excluded.status
         END,
         batch_hash = CASE
           WHEN event_resolutions.status = 'confirmed' THEN event_resolutions.batch_hash
           ELSE excluded.batch_hash
         END,
         attending_member_ids = CASE
           WHEN event_resolutions.status = 'confirmed'
             THEN event_resolutions.attending_member_ids
           ELSE excluded.attending_member_ids
         END,
         resolved_at = CASE
           WHEN event_resolutions.status = 'confirmed' THEN event_resolutions.resolved_at
           ELSE excluded.resolved_at
         END,
         updated_at = excluded.updated_at`
  ).bind(
    eventId,
    inputDigest,
    resolution.status,
    resolution.status === "pending" ? null : inputDigest,
    attendingMemberIds,
    resolvedAt,
    nowIso,
    nowIso
  ).run();
}
async function getSimpleEventResolution(db, bindings, event, nowIso = (/* @__PURE__ */ new Date()).toISOString()) {
  if (!event.invitationsSent || !event.rsvpDeadline) return null;
  const stored = await db.prepare(
    `SELECT status, attending_member_ids AS attendingMemberIds,
              resolved_at AS resolvedAt
       FROM event_resolutions WHERE event_id = ?`
  ).bind(event.id).first();
  const ballots = await loadLatestBallots(db, bindings, event);
  const memberIdByInviteeId = new Map(
    await Promise.all(event.invitees.map(async ({ id }) => [
      id,
      await deriveBallotMemberId(bindings, event.id, id)
    ]))
  );
  const ballotByInviteeId = new Map(ballots.map((ballot) => [ballot.inviteeId, ballot]));
  if (stored?.status === "confirmed" && stored.resolvedAt) {
    const attendingMemberIds = JSON.parse(stored.attendingMemberIds ?? "[]");
    const attendingInviteeIds2 = new Set(attendingMemberIds.filter((id) => id !== "host"));
    return {
      status: "confirmed",
      attendingMemberIds,
      attendanceRevealed: true,
      guestStates: event.invitees.map(({ id }) => {
        const ballot = ballotByInviteeId.get(id);
        return {
          memberId: id,
          status: attendingInviteeIds2.has(id) ? "going" : ballot ? "cant_commit" : "no_response",
          missedDeadline: false
        };
      }),
      resolvedAt: stored.resolvedAt
    };
  }
  const attending = new Set(
    ballots.filter((ballot) => ballot.response === "going").map((ballot) => ballot.memberId)
  );
  let changed = true;
  while (changed) {
    changed = false;
    const participantCount = attending.size + 1;
    for (const ballot of ballots) {
      if (!attending.has(ballot.memberId)) continue;
      if (ballot.minimumParticipants === null || ballot.minimumParticipants > participantCount || !groupsSatisfied(ballot.requiredGroups, attending)) {
        attending.delete(ballot.memberId);
        changed = true;
      }
    }
  }
  const hostGroups = event.requiredGroups.map((group) => ({
    memberIDs: group.memberIDs.flatMap((inviteeId) => {
      const memberId = memberIdByInviteeId.get(inviteeId);
      return memberId ? [memberId] : [];
    })
  }));
  const confirmed = attending.size + 1 >= event.minimumParticipants && groupsSatisfied(hostGroups, attending);
  const attendingInviteeIds = event.invitees.filter(({ id }) => {
    const memberId = memberIdByInviteeId.get(id);
    return memberId ? attending.has(memberId) : false;
  }).map(({ id }) => id);
  const inputDigest = await digest(JSON.stringify({
    protocolVersion: 2,
    eventId: event.id,
    minimumParticipants: event.minimumParticipants,
    requiredGroups: event.requiredGroups,
    inviteeIds: event.invitees.map(({ id }) => id),
    ballots: ballots.map((ballot) => ({
      memberId: ballot.memberId,
      response: ballot.response,
      minimumParticipants: ballot.minimumParticipants,
      requiredGroups: ballot.requiredGroups,
      createdAt: ballot.createdAt
    }))
  }));
  let resolution;
  if (confirmed) {
    resolution = {
      status: "confirmed",
      attendingMemberIds: ["host", ...attendingInviteeIds],
      attendanceRevealed: true,
      guestStates: event.invitees.map(({ id }) => {
        const ballot = ballotByInviteeId.get(id);
        const memberId = memberIdByInviteeId.get(id);
        return {
          memberId: id,
          status: ballot?.response === "cant_commit" ? "cant_commit" : attending.has(memberId) ? "going" : ballot ? "cant_commit" : "no_response",
          missedDeadline: false
        };
      }),
      resolvedAt: nowIso
    };
  } else if (nowIso >= event.rsvpDeadline) {
    resolution = { status: "not_confirmed", resolvedAt: nowIso };
  } else {
    resolution = { status: "pending" };
  }
  await persistResolution(db, event.id, inputDigest, resolution, nowIso);
  if (resolution.status !== "pending") {
    try {
      await sendResolutionTransitionNotifications(
        db,
        bindings,
        event,
        inputDigest,
        resolution.status
      );
    } catch (error) {
      console.error("Herd resolution notification failed", {
        eventId: event.id,
        error: error instanceof Error ? error.message : "unknown_error"
      });
    }
  }
  return resolution;
}

// invitee-web/lib/backend/resolutions.ts
var EVENT_RESOLUTION_SELECT = `SELECT
  event_id AS eventId,
  policy_hash AS policyHash,
  status,
  batch_hash AS batchHash,
  attending_member_ids AS attendingMemberIds,
  resolved_at AS resolvedAt,
  evaluation_lease_id AS evaluationLeaseId,
  evaluation_lease_expires_at AS evaluationLeaseExpiresAt,
  evaluation_request_hash AS evaluationRequestHash,
  result_attestation_protocol_version AS resultAttestationProtocolVersion,
  result_attestation_signing_key_id AS resultAttestationSigningKeyId,
  result_attestation_evaluated_at AS resultAttestationEvaluatedAt,
  result_attestation_canonical_document AS resultAttestationCanonicalDocument,
  result_attestation_signature AS resultAttestationSignature,
  created_at AS createdAt,
  updated_at AS updatedAt
FROM event_resolutions`;
var EVALUATION_LEASE_MILLISECONDS = 3e4;
var RELAY_EVALUATION_LEASE_MILLISECONDS = 9e4;
var RELAY_PADDED_PLAINTEXT_BYTES = 327680;
var RELAY_MAXIMUM_INNER_REQUEST_BYTES = 256 * 1024;
var RELAY_CIPHERTEXT_BYTES = RELAY_PADDED_PLAINTEXT_BYTES + 12 + 16;
var RELAY_KEY_INFO_LABEL = "HERD-EVALUATOR-RELAY-KEY-V1\0";
var RELAY_AAD_LABEL = "HERD-EVALUATOR-RELAY-AAD-V1\0";
var RELAY_CAPABILITY_LABEL = "HERD-EVALUATOR-RELAY-CAPABILITY-V1\0";
function isRecord2(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
function hasExactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
async function sha256Base64Url2(value) {
  const digest2 = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return bytesToBase64Url(new Uint8Array(digest2));
}
function isCanonicalBase64UrlBytes(value, bytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  try {
    const decoded = base64UrlToBytes(value);
    return decoded.length === bytes && bytesToBase64Url(decoded) === value;
  } catch {
    return false;
  }
}
function evaluationFailureCode(error) {
  if (error instanceof ApiError && /^[a-z0-9_]{1,80}$/u.test(error.code)) {
    return error.code;
  }
  return "unexpected_evaluation_error";
}
function reportEvaluationFailure(_eventId, error) {
  console.error("Herd event evaluation failed", {
    code: evaluationFailureCode(error)
  });
}
function storedResultAttestation(row) {
  const values = [
    row.resultAttestationProtocolVersion,
    row.resultAttestationSigningKeyId,
    row.resultAttestationEvaluatedAt,
    row.resultAttestationCanonicalDocument,
    row.resultAttestationSignature
  ];
  if (values.every((value) => value === null)) return void 0;
  if (row.resultAttestationProtocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || typeof row.resultAttestationSigningKeyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(
    row.resultAttestationSigningKeyId
  ) || typeof row.resultAttestationEvaluatedAt !== "string" || !Number.isFinite(Date.parse(row.resultAttestationEvaluatedAt)) || new Date(Date.parse(row.resultAttestationEvaluatedAt)).toISOString() !== row.resultAttestationEvaluatedAt || row.resultAttestationEvaluatedAt !== row.resolvedAt || typeof row.resultAttestationCanonicalDocument !== "string" || row.resultAttestationCanonicalDocument.length < 2 || row.resultAttestationCanonicalDocument.length > 32768 || !isCanonicalBase64UrlBytes(row.resultAttestationSignature, 64)) {
    return void 0;
  }
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    signingKeyId: row.resultAttestationSigningKeyId,
    evaluatedAt: row.resultAttestationEvaluatedAt,
    canonicalDocument: row.resultAttestationCanonicalDocument,
    signature: row.resultAttestationSignature
  };
}
function parseStoredResolution(row, eventId, policyHash) {
  if (!row) return null;
  if (row.eventId !== eventId || row.policyHash !== policyHash) {
    throw new ApiError(
      500,
      "event_resolution_corrupt",
      "The stored event result does not match its frozen policy."
    );
  }
  if (row.status === "pending") {
    if (row.batchHash || row.attendingMemberIds || row.resolvedAt || row.evaluationLeaseId || row.evaluationLeaseExpiresAt || row.evaluationRequestHash || row.resultAttestationProtocolVersion !== null || row.resultAttestationSigningKeyId !== null || row.resultAttestationEvaluatedAt !== null || row.resultAttestationCanonicalDocument !== null || row.resultAttestationSignature !== null) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid."
      );
    }
    return { status: "pending" };
  }
  if (row.status === "evaluating") {
    if (row.attendingMemberIds || row.resolvedAt || row.resultAttestationProtocolVersion !== null || row.resultAttestationSigningKeyId !== null || row.resultAttestationEvaluatedAt !== null || row.resultAttestationCanonicalDocument !== null || row.resultAttestationSignature !== null || !row.evaluationLeaseId || row.evaluationLeaseId.length > 80 || !row.evaluationLeaseExpiresAt || !Number.isFinite(Date.parse(row.evaluationLeaseExpiresAt)) || !(!row.batchHash && !row.evaluationRequestHash || isCanonicalBase64UrlBytes(row.batchHash, 32) && isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32))) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid."
      );
    }
    return { status: "pending" };
  }
  if (row.status === "not_confirmed") {
    if (!isCanonicalBase64UrlBytes(row.batchHash, 32) || row.attendingMemberIds || !row.resolvedAt || !Number.isFinite(Date.parse(row.resolvedAt)) || row.evaluationLeaseId || row.evaluationLeaseExpiresAt || row.evaluationRequestHash !== null && !isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32)) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid."
      );
    }
    const attestation = storedResultAttestation(row);
    return {
      status: "not_confirmed",
      resolvedAt: row.resolvedAt,
      ...attestation ? { attestation } : {}
    };
  }
  if (row.status === "confirmed") {
    const revealMigrationActive = row.attendingMemberIds === null && Boolean(
      row.evaluationLeaseId && row.evaluationLeaseExpiresAt && row.batchHash && row.evaluationRequestHash
    );
    if (!isCanonicalBase64UrlBytes(row.batchHash, 32) || !row.resolvedAt || !Number.isFinite(Date.parse(row.resolvedAt)) || !revealMigrationActive && (row.evaluationLeaseId || row.evaluationLeaseExpiresAt) || revealMigrationActive && (!isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32) || !row.evaluationLeaseExpiresAt || !Number.isFinite(Date.parse(row.evaluationLeaseExpiresAt))) || row.evaluationRequestHash !== null && !isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32)) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid."
      );
    }
    if (row.attendingMemberIds === null) {
      const attestation = storedResultAttestation(row);
      return {
        status: "confirmed",
        attendanceRevealed: false,
        resolvedAt: row.resolvedAt,
        ...attestation ? { attestation } : {}
      };
    }
    try {
      const attendingMemberIds = JSON.parse(row.attendingMemberIds);
      if (!Array.isArray(attendingMemberIds) || attendingMemberIds.length === 0 || attendingMemberIds.some((memberId) => typeof memberId !== "string") || new Set(attendingMemberIds).size !== attendingMemberIds.length) {
        throw new TypeError();
      }
      const attestation = storedResultAttestation(row);
      return {
        status: "confirmed",
        attendingMemberIds,
        attendanceRevealed: true,
        resolvedAt: row.resolvedAt,
        ...attestation ? { attestation } : {}
      };
    } catch {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid."
      );
    }
  }
  throw new ApiError(
    500,
    "event_resolution_corrupt",
    "The stored event result has an unsupported status."
  );
}
function requiresAttendanceReveal(row) {
  return row.status === "confirmed" && row.attendingMemberIds === null;
}
async function withRevealedGuestStates(db, event, resolution) {
  if (resolution?.status !== "confirmed" || !resolution.attendanceRevealed || !resolution.attendingMemberIds || !event.rsvpDeadline) {
    return resolution;
  }
  const rows = await db.prepare(
    `SELECT invitees.id AS memberId,
              MIN(response_envelopes.created_at) AS firstResponseAt
       FROM invitees
       LEFT JOIN response_envelopes
         ON response_envelopes.invitee_id = invitees.id
       WHERE invitees.event_id = ?
       GROUP BY invitees.id
       ORDER BY invitees.id ASC`
  ).bind(event.id).all();
  const attending = new Set(resolution.attendingMemberIds);
  return {
    ...resolution,
    guestStates: rows.results.map(({ memberId, firstResponseAt }) => ({
      memberId,
      status: attending.has(memberId) ? "going" : firstResponseAt ? "cant_commit" : "no_response",
      missedDeadline: !firstResponseAt || firstResponseAt > event.rsvpDeadline
    }))
  };
}
async function loadResolutionRow(db, eventId) {
  return db.prepare(`${EVENT_RESOLUTION_SELECT} WHERE event_id = ?`).bind(eventId).first();
}
function prepareInsertPendingEventResolution(db, eventId, policyHash, nowIso) {
  return db.prepare(
    `INSERT OR IGNORE INTO event_resolutions
        (event_id, policy_hash, status, batch_hash, attending_member_ids,
         resolved_at, evaluation_lease_id, evaluation_lease_expires_at,
         evaluation_request_hash, result_attestation_protocol_version,
         result_attestation_signing_key_id, result_attestation_evaluated_at,
         result_attestation_canonical_document, result_attestation_signature,
         created_at, updated_at)
       VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, NULL, NULL,
               NULL, NULL, NULL, NULL, NULL, ?, ?)`
  ).bind(eventId, policyHash, nowIso, nowIso);
}
async function ensurePendingResolution(db, eventId, policyHash, nowIso) {
  await prepareInsertPendingEventResolution(db, eventId, policyHash, nowIso).run();
  let row = await loadResolutionRow(db, eventId);
  if (row && row.policyHash !== policyHash && row.status === "pending" && row.batchHash === null && row.attendingMemberIds === null && row.resolvedAt === null && row.evaluationLeaseId === null && row.evaluationLeaseExpiresAt === null && row.evaluationRequestHash === null && row.resultAttestationProtocolVersion === null && row.resultAttestationSigningKeyId === null && row.resultAttestationEvaluatedAt === null && row.resultAttestationCanonicalDocument === null && row.resultAttestationSignature === null) {
    await db.prepare(
      `DELETE FROM event_resolutions
          WHERE event_id = ? AND policy_hash = ? AND status = 'pending'
            AND batch_hash IS NULL AND attending_member_ids IS NULL
            AND resolved_at IS NULL AND evaluation_lease_id IS NULL
            AND evaluation_lease_expires_at IS NULL
            AND evaluation_request_hash IS NULL
            AND result_attestation_protocol_version IS NULL
            AND result_attestation_signing_key_id IS NULL
            AND result_attestation_evaluated_at IS NULL
            AND result_attestation_canonical_document IS NULL
            AND result_attestation_signature IS NULL`
    ).bind(eventId, row.policyHash).run();
    await prepareInsertPendingEventResolution(db, eventId, policyHash, nowIso).run();
    row = await loadResolutionRow(db, eventId);
  }
  if (!row) {
    throw new ApiError(
      500,
      "event_resolution_unavailable",
      "The event result could not be initialized."
    );
  }
  parseStoredResolution(row, eventId, policyHash);
  return row;
}
async function canonicalPolicyFacts(bindings, event, policy) {
  if (policy.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || policy.cipherSuite !== PRIVATE_RESPONSE_CIPHER_SUITE || policy.paddedPlaintextBytes !== PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES || await sha256Base64Url2(policy.canonicalDocument) !== policy.policyHash || !await verifyStoredEventPolicyCertification(bindings, policy)) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be validated."
    );
  }
  let document;
  try {
    const parsed = JSON.parse(policy.canonicalDocument);
    if (!isRecord2(parsed)) throw new TypeError();
    document = parsed;
  } catch {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be validated."
    );
  }
  const eventDocument = document.event;
  const evaluator = document.evaluator;
  const hostRules = document.hostRules;
  if (document.protocolVersion !== policy.protocolVersion || document.cipherSuite !== policy.cipherSuite || document.rsvpDeadline !== event.rsvpDeadline || document.releaseId !== policy.releaseId || !isRecord2(eventDocument) || eventDocument.id !== event.id || !isRecord2(evaluator) || evaluator.keyId !== policy.evaluatorKeyId || evaluator.publicKey !== policy.evaluatorPublicKey || evaluator.measurement !== policy.evaluatorMeasurement || !isRecord2(hostRules) || !Number.isInteger(hostRules.minimumParticipants) || !Array.isArray(hostRules.requiredGroups) || !Array.isArray(document.members)) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be validated."
    );
  }
  const inviteeIds = [];
  for (const member of document.members) {
    if (!isRecord2(member) || typeof member.id !== "string" || !member.id) {
      throw new ApiError(
        500,
        "event_policy_corrupt",
        "The frozen event policy contains an invalid member."
      );
    }
    inviteeIds.push(member.id);
  }
  if (new Set(inviteeIds).size !== inviteeIds.length || inviteeIds.some((id, index) => index > 0 && inviteeIds[index - 1].localeCompare(id) >= 0)) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy contains invalid membership."
    );
  }
  const requiredGroups = [];
  for (const group of hostRules.requiredGroups) {
    if (!isRecord2(group) || typeof group.id !== "string" || !Array.isArray(group.memberIDs) || group.memberIDs.some((id) => typeof id !== "string" || !inviteeIds.includes(id))) {
      throw new ApiError(
        500,
        "event_policy_corrupt",
        "The frozen event policy contains invalid attendance rules."
      );
    }
    requiredGroups.push({
      id: group.id,
      memberIDs: group.memberIDs
    });
  }
  return {
    inviteeIds,
    minimumParticipants: hostRules.minimumParticipants,
    requiredGroups
  };
}
async function loadBallotEvaluatorSlots(db, bindings, event, policy, facts) {
  const rows = await db.prepare(
    `SELECT revisions.ballot_id AS ballotId,
              revisions.revision,
              revisions.response,
              revisions.minimum_participants AS minimumParticipants,
              revisions.required_groups AS requiredGroups
       FROM ballot_revisions AS revisions
       JOIN (
         SELECT ballot_id, MAX(revision) AS revision
         FROM ballot_revisions
         WHERE event_id = ?
         GROUP BY ballot_id
       ) AS latest
         ON latest.ballot_id = revisions.ballot_id
        AND latest.revision = revisions.revision
       WHERE revisions.event_id = ?`
  ).bind(event.id, event.id).all();
  if (rows.results.length === 0) return /* @__PURE__ */ new Map();
  const identityEntries = await Promise.all(facts.inviteeIds.map(async (inviteeId) => [
    await deriveBallotId(bindings, event.id, inviteeId),
    inviteeId
  ]));
  const inviteeByBallot = new Map(identityEntries);
  const memberEntries = await Promise.all(facts.inviteeIds.map(async (inviteeId) => [
    await deriveBallotMemberId(bindings, event.id, inviteeId),
    inviteeId
  ]));
  const inviteeByMember = new Map(memberEntries);
  const result = /* @__PURE__ */ new Map();
  for (const row of rows.results) {
    const inviteeId = inviteeByBallot.get(row.ballotId);
    if (!inviteeId) continue;
    const cached = await db.prepare(
      `SELECT envelope, envelope_hash AS envelopeHash
         FROM ballot_evaluation_slots
         WHERE ballot_id = ? AND revision = ?`
    ).bind(row.ballotId, row.revision).first();
    if (cached) {
      try {
        const envelope = JSON.parse(cached.envelope);
        if (envelope.eventId === event.id && envelope.inviteeId === inviteeId && envelope.policyHash === policy.policyHash && await responseEnvelopeHash(envelope) === cached.envelopeHash) {
          result.set(inviteeId, { ...envelope, ciphertextHash: cached.envelopeHash });
          continue;
        }
      } catch {
      }
    }
    let storedGroups;
    try {
      storedGroups = JSON.parse(row.requiredGroups);
      if (!Array.isArray(storedGroups)) throw new Error("invalid groups");
    } catch {
      throw new ApiError(500, "ballot_corrupt", "A private ballot could not be evaluated.");
    }
    const requiredGroups = storedGroups.map((group) => ({
      id: group.id,
      memberIDs: group.memberIDs.map((memberId) => {
        const resolved = inviteeByMember.get(memberId);
        if (!resolved) {
          throw new ApiError(500, "ballot_corrupt", "A private ballot could not be evaluated.");
        }
        return resolved;
      })
    }));
    const rootSecret = crypto.getRandomValues(new Uint8Array(32));
    const sealed = await sealPrivateResponse(
      {
        eventId: event.id,
        inviteeId,
        accountKeyEpochId: crypto.randomUUID(),
        revision: row.revision,
        response: row.response,
        minimumParticipants: row.minimumParticipants,
        requiredGroups,
        allowedInviteeIds: facts.inviteeIds,
        accountRootSecret: rootSecret,
        policy
      },
      // canonicalPolicyFacts authenticated the stored signature and exact
      // evaluator descriptor immediately before this bridge is constructed.
      {
        evaluatorKeyId: policy.evaluatorKeyId,
        evaluatorPublicKey: policy.evaluatorPublicKey
      }
    ).finally(() => rootSecret.fill(0));
    const envelopeHash = await responseEnvelopeHash(sealed.envelope);
    await db.prepare(
      `INSERT INTO ballot_evaluation_slots (
           ballot_id, revision, event_id, envelope, envelope_hash, created_at
         ) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(ballot_id, revision) DO UPDATE SET
           envelope = excluded.envelope,
           envelope_hash = excluded.envelope_hash,
           created_at = excluded.created_at`
    ).bind(
      row.ballotId,
      row.revision,
      event.id,
      JSON.stringify(sealed.envelope),
      envelopeHash,
      (/* @__PURE__ */ new Date()).toISOString()
    ).run();
    result.set(inviteeId, { ...sealed.envelope, ciphertextHash: envelopeHash });
  }
  return result;
}
async function buildEvaluatorBatch(db, bindings, event, policy, facts, nowIso) {
  const databaseMembers = await db.prepare("SELECT id FROM invitees WHERE event_id = ? ORDER BY id ASC").bind(event.id).all();
  if (databaseMembers.results.length !== facts.inviteeIds.length || databaseMembers.results.some((member, index) => member.id !== facts.inviteeIds[index])) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "Event membership no longer matches the frozen policy."
    );
  }
  await recoverPendingResponseTransparency(db, bindings);
  const rows = await db.prepare(
    `${RESPONSE_ENVELOPE_SELECT}
       WHERE event_id = ?
         AND EXISTS (
           SELECT 1
           FROM response_transparency_entries AS certified_entries
           JOIN response_transparency_heads AS certified_heads
             ON certified_heads.log_index = certified_entries.log_index
            AND certified_heads.log_id = certified_entries.log_id
            AND certified_heads.head_entry_hash = certified_entries.entry_hash
            AND certified_heads.signing_key_id = certified_entries.signing_key_id
           WHERE certified_entries.envelope_id = response_envelopes.id
             AND certified_entries.receipt_signature IS NOT NULL
             AND certified_entries.signed_at IS NOT NULL
         )
       ORDER BY invitee_id ASC, revision DESC, created_at DESC`
  ).bind(event.id).all();
  const inviteeSet = new Set(facts.inviteeIds);
  const latest = /* @__PURE__ */ new Map();
  for (const row of rows.results) {
    if (!inviteeSet.has(row.inviteeId) || latest.has(row.inviteeId)) continue;
    const stored = parseResponseEnvelope(row);
    if (!stored || stored.eventId !== event.id || stored.inviteeId !== row.inviteeId || stored.policyHash !== policy.policyHash || stored.evaluatorKeyId !== policy.evaluatorKeyId) {
      continue;
    }
    const envelope = unstoredResponseEnvelope(stored);
    const ciphertextHash = await responseEnvelopeHash(envelope);
    if (ciphertextHash !== stored.ciphertextHash) continue;
    latest.set(row.inviteeId, { ...envelope, ciphertextHash });
  }
  const ballotSlots = await loadBallotEvaluatorSlots(db, bindings, event, policy, facts);
  for (const [inviteeId, envelope] of ballotSlots) latest.set(inviteeId, envelope);
  const slots = facts.inviteeIds.map((inviteeId) => {
    const response = latest.get(inviteeId);
    if (!response) return { inviteeId, envelopeHash: null, envelope: null };
    const { ciphertextHash, ...envelope } = response;
    return { inviteeId, envelopeHash: ciphertextHash, envelope };
  });
  const revealAttendance = true;
  const batchDocument = JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: event.id,
    policyHash: policy.policyHash,
    revealAttendance,
    slots: slots.map(({ inviteeId, envelopeHash }) => ({
      inviteeId,
      envelopeHash
    }))
  });
  const batchHash = await sha256Base64Url2(batchDocument);
  const ballotInputs = await db.prepare(
    `SELECT ballot_id AS ballotId, MAX(revision) AS revision
     FROM ballot_revisions
     WHERE event_id = ?
     GROUP BY ballot_id
     ORDER BY ballot_id`
  ).bind(event.id).all();
  if (ballotInputs.results.length > 0) {
    await db.prepare(
      `INSERT INTO ballot_evaluation_runs (
         id, event_id, input_digest, input_revisions, status,
         attending_member_ids, error_code, source, reason, created_at
       ) VALUES (?, ?, ?, ?, 'prepared', NULL, NULL, 'automatic', NULL, ?)
       ON CONFLICT(event_id, input_digest) DO NOTHING`
    ).bind(
      crypto.randomUUID(),
      event.id,
      batchHash,
      JSON.stringify(ballotInputs.results),
      nowIso
    ).run();
  }
  return {
    batchHash,
    revealAttendance,
    slots
  };
}
function evaluatorPolicyDescriptor(policy) {
  const {
    policySigningKeyId: _policySigningKeyId,
    policySignature: _policySignature,
    ...descriptor
  } = policy;
  void _policySigningKeyId;
  void _policySignature;
  return descriptor;
}
function validateEvaluatorResult(value, event, policy, facts, batchHash, revealAttendance) {
  if (!isRecord2(value) || value.status !== "confirmed" && value.status !== "not_confirmed") {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned an invalid result.");
  }
  const legacyFormat = revealAttendance && !("revealAttendance" in value);
  const expectedKeys = [
    "protocolVersion",
    "eventId",
    "policyHash",
    "batchHash",
    "evaluatorKeyId",
    "status",
    ...legacyFormat ? [] : ["revealAttendance"],
    ...value.status === "confirmed" && revealAttendance ? ["attendingMemberIds"] : []
  ];
  if (!hasExactKeys(value, expectedKeys) || value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || value.eventId !== event.id || value.policyHash !== policy.policyHash || value.batchHash !== batchHash || value.evaluatorKeyId !== policy.evaluatorKeyId || !legacyFormat && value.revealAttendance !== revealAttendance) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned an invalid result.");
  }
  if (value.status === "not_confirmed") {
    return { status: "not_confirmed", revealAttendance, legacyFormat };
  }
  if (!revealAttendance) {
    return { status: "confirmed", revealAttendance: false, legacyFormat: false };
  }
  if (!Array.isArray(value.attendingMemberIds) || value.attendingMemberIds.some((id) => typeof id !== "string") || new Set(value.attendingMemberIds).size !== value.attendingMemberIds.length) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned invalid attendance.");
  }
  const attendingMemberIds = value.attendingMemberIds;
  const attending = new Set(attendingMemberIds);
  const ordered = ["host", ...facts.inviteeIds.filter((id) => attending.has(id))];
  if (!attending.has("host") || ordered.length !== attending.size || ordered.some((id, index) => attendingMemberIds[index] !== id) || ordered.length < facts.minimumParticipants || facts.requiredGroups.some(
    (group) => !group.memberIDs.some((memberId) => attending.has(memberId))
  )) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned invalid attendance.");
  }
  return {
    status: "confirmed",
    revealAttendance: true,
    attendingMemberIds: ordered,
    legacyFormat
  };
}
async function callEvaluator(bindings, event, policy, facts, batchHash, revealAttendance, slots) {
  const service = getEvaluatorServiceConfig(bindings);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1e4);
  let response;
  try {
    response = await fetch(service.url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${service.token}`,
        "content-type": "application/json",
        accept: "application/json",
        ...service.sitesBypassToken ? {
          "OAI-Sites-Authorization": `Bearer ${service.sitesBypassToken}`
        } : {}
      },
      body: JSON.stringify({
        protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
        eventId: event.id,
        policy: evaluatorPolicyDescriptor(policy),
        batchHash,
        revealAttendance,
        slots
      }),
      redirect: "manual",
      signal: controller.signal
    });
  } catch (error) {
    const code = error instanceof Error && error.name === "AbortError" ? "evaluator_request_timeout" : "evaluator_network_error";
    throw new ApiError(
      503,
      code,
      "The private event result is temporarily unavailable."
    );
  } finally {
    clearTimeout(timeout);
  }
  if (!response.ok) {
    throw new ApiError(
      503,
      `evaluator_http_${response.status}`,
      "The private event result is temporarily unavailable."
    );
  }
  const text = await response.text();
  if (text.length > 32768) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned an invalid result.");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned an invalid result.");
  }
  return validateEvaluatorResult(
    value,
    event,
    policy,
    facts,
    batchHash,
    revealAttendance
  );
}
function utf8(value) {
  return new TextEncoder().encode(value);
}
function ownedArrayBuffer3(value) {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}
function canonicalRelayContext(evaluatorKeyId2, ephemeralPublicKey, salt) {
  return JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    evaluatorKeyId: evaluatorKeyId2,
    ephemeralPublicKey,
    salt
  });
}
async function sealEvaluatorRelayRequest(evaluatorKeyId2, evaluatorPublicKey2, capabilityToken, wrapper) {
  const wrapperBytes = utf8(JSON.stringify(wrapper));
  if (wrapperBytes.length > RELAY_MAXIMUM_INNER_REQUEST_BYTES || wrapperBytes.length + 4 > RELAY_PADDED_PLAINTEXT_BYTES) {
    throw new ApiError(
      500,
      "evaluation_batch_too_large",
      "The private event evaluation request is too large."
    );
  }
  const plaintext = new Uint8Array(RELAY_PADDED_PLAINTEXT_BYTES);
  new DataView(plaintext.buffer).setUint32(0, wrapperBytes.length, false);
  plaintext.set(wrapperBytes, 4);
  let evaluatorKey;
  try {
    evaluatorKey = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer3(base64UrlToBytes(evaluatorPublicKey2)),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator encryption key is invalid."
    );
  }
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephemeralPublicKey = bytesToBase64Url(
    new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey))
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: evaluatorKey },
      ephemeral.privateKey,
      256
    )
  );
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const salt = bytesToBase64Url(saltBytes);
  const context = canonicalRelayContext(
    evaluatorKeyId2,
    ephemeralPublicKey,
    salt
  );
  const hkdfMaterial = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer3(sharedSecret),
    "HKDF",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: ownedArrayBuffer3(saltBytes),
      info: ownedArrayBuffer3(
        concatenateBytes(utf8(RELAY_KEY_INFO_LABEL), utf8(context))
      )
    },
    hkdfMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: ownedArrayBuffer3(iv),
        additionalData: ownedArrayBuffer3(
          concatenateBytes(utf8(RELAY_AAD_LABEL), utf8(context))
        ),
        tagLength: 128
      },
      aesKey,
      ownedArrayBuffer3(plaintext)
    )
  );
  const ciphertextBytes = concatenateBytes(iv, encrypted);
  if (ciphertextBytes.length !== RELAY_CIPHERTEXT_BYTES) {
    throw new ApiError(
      500,
      "evaluation_relay_unavailable",
      "The private event evaluation request could not be sealed."
    );
  }
  const unsignedRequest = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    evaluatorKeyId: evaluatorKeyId2,
    ephemeralPublicKey,
    salt,
    ciphertext: bytesToBase64Url(ciphertextBytes)
  };
  const capabilityKey = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer3(utf8(capabilityToken)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const capabilityMac = bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        capabilityKey,
        ownedArrayBuffer3(
          concatenateBytes(
            utf8(RELAY_CAPABILITY_LABEL),
            utf8(JSON.stringify(unsignedRequest))
          )
        )
      )
    )
  );
  const relayRequest = { ...unsignedRequest, capabilityMac };
  return {
    relayRequest,
    requestHash: await sha256Base64Url2(JSON.stringify(relayRequest))
  };
}
async function acquireRelayEvaluationLease(db, eventId, policyHash, batchHash, requestHash, leaseId, leaseExpiresAt, nowIso) {
  const acquired = await db.prepare(
    `UPDATE event_resolutions
       SET status = CASE WHEN status = 'confirmed' THEN 'confirmed' ELSE 'evaluating' END,
           batch_hash = ?,
           evaluation_request_hash = ?,
           evaluation_lease_id = ?,
           evaluation_lease_expires_at = ?,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND (
           status = 'pending'
           OR (
             status = 'confirmed'
             AND attending_member_ids IS NULL
             AND resolved_at IS NOT NULL
             AND (
               evaluation_lease_id IS NULL
               OR evaluation_lease_expires_at <= ?
             )
           )
           OR (
             status = 'evaluating'
             AND evaluation_lease_expires_at <= ?
           )
         )`
  ).bind(
    batchHash,
    requestHash,
    leaseId,
    leaseExpiresAt,
    nowIso,
    eventId,
    policyHash,
    nowIso,
    nowIso
  ).run();
  return (acquired.meta.changes ?? 0) === 1;
}
async function acquireEvaluationLease(db, eventId, policyHash, nowIso) {
  const leaseId = crypto.randomUUID();
  const leaseExpiresAt = new Date(
    Date.parse(nowIso) + EVALUATION_LEASE_MILLISECONDS
  ).toISOString();
  const acquired = await db.prepare(
    `UPDATE event_resolutions
       SET status = 'evaluating',
           batch_hash = NULL,
           evaluation_request_hash = NULL,
           evaluation_lease_id = ?,
           evaluation_lease_expires_at = ?,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND (
           status = 'pending'
           OR (
             status = 'evaluating'
             AND evaluation_lease_expires_at <= ?
           )
         )`
  ).bind(
    leaseId,
    leaseExpiresAt,
    nowIso,
    eventId,
    policyHash,
    nowIso
  ).run();
  return (acquired.meta.changes ?? 0) === 1 ? leaseId : null;
}
async function resetEvaluationLease(db, eventId, policyHash, leaseId) {
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  const released = await db.prepare(
    `UPDATE event_resolutions
       SET status = CASE WHEN status = 'confirmed' THEN 'confirmed' ELSE 'pending' END,
           batch_hash = CASE WHEN status = 'confirmed' THEN batch_hash ELSE NULL END,
           evaluation_request_hash = CASE
             WHEN status = 'confirmed' THEN evaluation_request_hash
             ELSE NULL
           END,
           evaluation_lease_id = NULL,
           evaluation_lease_expires_at = NULL,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND status IN ('evaluating', 'confirmed')
         AND evaluation_lease_id = ?`
  ).bind(nowIso, eventId, policyHash, leaseId).run();
  return (released.meta.changes ?? 0) === 1;
}
async function resetPrematureNotConfirmedResolution(db, event, policyHash, nowIso) {
  if (!event.rsvpDeadline) return false;
  const reset = await db.prepare(
    `UPDATE event_resolutions
       SET status = 'pending',
           batch_hash = NULL,
           attending_member_ids = NULL,
           resolved_at = NULL,
           evaluation_request_hash = NULL,
           evaluation_lease_id = NULL,
           evaluation_lease_expires_at = NULL,
           result_attestation_protocol_version = NULL,
           result_attestation_signing_key_id = NULL,
           result_attestation_evaluated_at = NULL,
           result_attestation_canonical_document = NULL,
           result_attestation_signature = NULL,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND status = 'not_confirmed'
         AND resolved_at IS NOT NULL
         AND resolved_at < ?`
  ).bind(nowIso, event.id, policyHash, event.rsvpDeadline).run();
  return (reset.meta.changes ?? 0) === 1;
}
async function releaseClientRelayEvaluationLease(db, eventId, policyHash, leaseId) {
  return resetEvaluationLease(db, eventId, policyHash, leaseId);
}
async function startClientRelayEvaluation(db, bindings, event, nowIso = (/* @__PURE__ */ new Date()).toISOString()) {
  const relay = getEvaluatorRelayConfig(bindings);
  if (!event.invitationsSent || !event.privateResponsePolicy || !event.rsvpDeadline) {
    throw new ApiError(
      409,
      "evaluation_not_ready",
      "This event is not ready for private evaluation."
    );
  }
  const policy = event.privateResponsePolicy;
  if (policy.evaluatorKeyId !== relay.evaluatorKeyId || policy.evaluatorPublicKey !== relay.evaluatorPublicKey) {
    throw new ApiError(
      503,
      "evaluation_key_unavailable",
      "The frozen event evaluator key is not available."
    );
  }
  const row = await ensurePendingResolution(
    db,
    event.id,
    policy.policyHash,
    nowIso
  );
  const needsAttendanceReveal = requiresAttendanceReveal(row);
  const existing = parseStoredResolution(row, event.id, policy.policyHash);
  if (existing.status !== "pending" && !needsAttendanceReveal) {
    return { kind: "resolved", resolution: existing };
  }
  if (row.evaluationLeaseExpiresAt && row.evaluationLeaseExpiresAt > nowIso) {
    return { kind: "pending" };
  }
  const facts = await canonicalPolicyFacts(bindings, event, policy);
  const { batchHash, revealAttendance, slots } = await buildEvaluatorBatch(
    db,
    bindings,
    event,
    policy,
    facts,
    nowIso
  );
  const relayRequestId = crypto.randomUUID();
  const leaseId = crypto.randomUUID();
  const expiresAt = new Date(
    Date.parse(nowIso) + RELAY_EVALUATION_LEASE_MILLISECONDS
  ).toISOString();
  const evaluationRequest = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: event.id,
    policy: evaluatorPolicyDescriptor(policy),
    batchHash,
    revealAttendance,
    slots
  };
  const { relayRequest, requestHash } = await sealEvaluatorRelayRequest(
    relay.evaluatorKeyId,
    relay.evaluatorPublicKey,
    relay.token,
    {
      protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
      relayRequestId,
      leaseId,
      issuedAt: nowIso,
      expiresAt,
      evaluationRequest
    }
  );
  const acquired = await acquireRelayEvaluationLease(
    db,
    event.id,
    policy.policyHash,
    batchHash,
    requestHash,
    leaseId,
    expiresAt,
    nowIso
  );
  if (!acquired) {
    const current = await loadResolutionRow(db, event.id);
    const resolution = parseStoredResolution(current, event.id, policy.policyHash);
    return resolution && resolution.status !== "pending" ? { kind: "resolved", resolution } : { kind: "pending" };
  }
  return {
    kind: "relay",
    job: {
      eventId: event.id,
      evaluatorUrl: relay.url,
      evaluatorHost: relay.evaluatorHost,
      releaseId: policy.releaseId,
      leaseId,
      expiresAt,
      relayRequest
    }
  };
}
function invalidRelayAttestation() {
  throw new ApiError(
    400,
    "invalid_evaluator_attestation",
    "The evaluator result could not be verified."
  );
}
function canonicalUuid(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
    value
  )) {
    invalidRelayAttestation();
  }
  return value;
}
function canonicalIsoTimestamp(value) {
  if (typeof value !== "string") invalidRelayAttestation();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRelayAttestation();
  }
  return value;
}
async function completeClientRelayEvaluation(db, bindings, event, value, nowIso = (/* @__PURE__ */ new Date()).toISOString()) {
  const relay = getEvaluatorRelayConfig(bindings);
  if (!event.invitationsSent || !event.privateResponsePolicy || !event.rsvpDeadline) {
    throw new ApiError(
      409,
      "evaluation_not_ready",
      "This event is not ready for private evaluation."
    );
  }
  const policy = event.privateResponsePolicy;
  if (policy.evaluatorKeyId !== relay.evaluatorKeyId || policy.evaluatorPublicKey !== relay.evaluatorPublicKey) {
    throw new ApiError(
      503,
      "evaluation_key_unavailable",
      "The frozen event evaluator key is not available."
    );
  }
  const row = await ensurePendingResolution(
    db,
    event.id,
    policy.policyHash,
    nowIso
  );
  const existing = parseStoredResolution(row, event.id, policy.policyHash);
  const isAttendanceRevealMigration = row.status === "confirmed" && row.attendingMemberIds === null;
  if (existing.status !== "pending" && !isAttendanceRevealMigration) return existing;
  if (row.status !== "evaluating" && !isAttendanceRevealMigration || !row.batchHash || !row.evaluationRequestHash || !row.evaluationLeaseId || !row.evaluationLeaseExpiresAt || row.evaluationLeaseExpiresAt <= nowIso) {
    throw new ApiError(
      409,
      "evaluation_lease_stale",
      "The evaluation lease is no longer active."
    );
  }
  if (!isRecord2(value)) invalidRelayAttestation();
  if (!hasExactKeys(value, [
    "protocolVersion",
    "relayRequestHash",
    "relayRequestId",
    "leaseId",
    "result",
    "attestation"
  ]) || value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || !isCanonicalBase64UrlBytes(value.relayRequestHash, 32) || value.relayRequestHash !== row.evaluationRequestHash) {
    invalidRelayAttestation();
  }
  const relayRequestId = canonicalUuid(value.relayRequestId);
  const leaseId = canonicalUuid(value.leaseId);
  if (leaseId !== row.evaluationLeaseId) invalidRelayAttestation();
  const facts = await canonicalPolicyFacts(bindings, event, policy);
  const evaluatorResult = validateEvaluatorResult(
    value.result,
    event,
    policy,
    facts,
    row.batchHash,
    isRecord2(value.result) && value.result.revealAttendance === true
  );
  const canonicalResult = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: event.id,
    policyHash: policy.policyHash,
    batchHash: row.batchHash,
    evaluatorKeyId: policy.evaluatorKeyId,
    status: evaluatorResult.status,
    ...evaluatorResult.legacyFormat ? {} : { revealAttendance: evaluatorResult.revealAttendance },
    ...evaluatorResult.status === "confirmed" && evaluatorResult.revealAttendance ? { attendingMemberIds: evaluatorResult.attendingMemberIds } : {}
  };
  if (!isRecord2(value.attestation)) invalidRelayAttestation();
  const attestation = value.attestation;
  if (!hasExactKeys(attestation, [
    "protocolVersion",
    "signingKeyId",
    "evaluatedAt",
    "canonicalDocument",
    "signature"
  ]) || attestation.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION || attestation.signingKeyId !== relay.resultSigningKeyId || typeof attestation.canonicalDocument !== "string" || attestation.canonicalDocument.length > 32768 || !isCanonicalBase64UrlBytes(attestation.signature, 64)) {
    invalidRelayAttestation();
  }
  const evaluatedAt = canonicalIsoTimestamp(attestation.evaluatedAt);
  if (evaluatedAt > row.evaluationLeaseExpiresAt || Date.parse(evaluatedAt) > Date.parse(nowIso) + 3e4) {
    invalidRelayAttestation();
  }
  const canonicalDocument = JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    signingKeyId: relay.resultSigningKeyId,
    relayRequestHash: row.evaluationRequestHash,
    relayRequestId,
    leaseId,
    evaluatedAt,
    result: canonicalResult
  });
  if (attestation.canonicalDocument !== canonicalDocument) {
    invalidRelayAttestation();
  }
  let signingPublicKey;
  try {
    signingPublicKey = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer3(base64UrlToBytes(relay.resultSigningPublicKey)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator result signing key is invalid."
    );
  }
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingPublicKey,
      ownedArrayBuffer3(base64UrlToBytes(attestation.signature)),
      ownedArrayBuffer3(utf8(canonicalDocument))
    );
  } catch {
    invalidRelayAttestation();
  }
  if (!verified) invalidRelayAttestation();
  if (!isAttendanceRevealMigration && evaluatorResult.status === "not_confirmed" && evaluatedAt < event.rsvpDeadline) {
    const released = await resetEvaluationLease(
      db,
      event.id,
      policy.policyHash,
      leaseId
    );
    if (!released) {
      const current = parseStoredResolution(
        await loadResolutionRow(db, event.id),
        event.id,
        policy.policyHash
      );
      if (current && current.status !== "pending") return current;
      if (current?.status === "pending") return current;
      throw new ApiError(
        409,
        "evaluation_lease_stale",
        "The evaluation lease is no longer active."
      );
    }
    return { status: "pending" };
  }
  const attendingMemberIds = evaluatorResult.status === "confirmed" && evaluatorResult.revealAttendance ? JSON.stringify(evaluatorResult.attendingMemberIds) : null;
  const persisted = await db.prepare(
    `UPDATE event_resolutions
       SET status = ?,
           attending_member_ids = ?,
           resolved_at = ?,
           result_attestation_protocol_version = ?,
           result_attestation_signing_key_id = ?,
           result_attestation_evaluated_at = ?,
           result_attestation_canonical_document = ?,
           result_attestation_signature = ?,
           evaluation_lease_id = NULL,
           evaluation_lease_expires_at = NULL,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND (
           status = 'evaluating'
           OR (status = 'confirmed' AND attending_member_ids IS NULL)
         )
         AND batch_hash = ?
         AND evaluation_request_hash = ?
         AND evaluation_lease_id = ?
         AND evaluation_lease_expires_at > ?`
  ).bind(
    evaluatorResult.status,
    attendingMemberIds,
    evaluatedAt,
    PRIVATE_RESPONSE_PROTOCOL_VERSION,
    attestation.signingKeyId,
    evaluatedAt,
    attestation.canonicalDocument,
    attestation.signature,
    nowIso,
    event.id,
    policy.policyHash,
    row.batchHash,
    row.evaluationRequestHash,
    leaseId,
    nowIso
  ).run();
  const finalRow = await loadResolutionRow(db, event.id);
  const finalResolution = parseStoredResolution(finalRow, event.id, policy.policyHash);
  if ((persisted.meta.changes ?? 0) !== 1) {
    if (finalResolution && finalResolution.status !== "pending") return finalResolution;
    throw new ApiError(
      409,
      "evaluation_lease_stale",
      "The evaluation lease is no longer active."
    );
  }
  if (!finalResolution || finalResolution.status === "pending") {
    throw new ApiError(
      500,
      "event_resolution_unavailable",
      "The private event result could not be saved."
    );
  }
  await db.prepare(
    `UPDATE ballot_evaluation_runs
     SET status = ?, attending_member_ids = NULL, error_code = NULL
     WHERE event_id = ? AND input_digest = ?`
  ).bind(evaluatorResult.status, event.id, row.batchHash).run();
  try {
    await sendResolutionTransitionNotifications(
      db,
      bindings,
      event,
      row.batchHash,
      evaluatorResult.status
    );
  } catch (error) {
    reportEvaluationFailure(event.id, error);
  }
  return finalResolution;
}
async function getEventResolutionForRead(db, bindings, event, nowIso = (/* @__PURE__ */ new Date()).toISOString()) {
  if (!event.invitationsSent) return null;
  if (!event.privateResponsePolicy) {
    if (event.minimumParticipants === void 0 || event.requiredGroups === void 0 || event.invitees === void 0) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The event is missing the information needed to calculate its result."
      );
    }
    return getSimpleEventResolution(
      db,
      bindings,
      {
        ...event,
        minimumParticipants: event.minimumParticipants,
        requiredGroups: event.requiredGroups,
        invitees: event.invitees
      },
      nowIso
    );
  }
  if (!event.rsvpDeadline) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "A sent event is missing its reply deadline."
    );
  }
  const row = await ensurePendingResolution(
    db,
    event.id,
    event.privateResponsePolicy.policyHash,
    nowIso
  );
  const resolution = parseStoredResolution(
    row,
    event.id,
    event.privateResponsePolicy.policyHash
  );
  if (resolution.status === "not_confirmed" && resolution.resolvedAt < event.rsvpDeadline) {
    const reset = await resetPrematureNotConfirmedResolution(
      db,
      event,
      event.privateResponsePolicy.policyHash,
      nowIso
    );
    if (reset) return { status: "pending" };
    const current = parseStoredResolution(
      await loadResolutionRow(db, event.id),
      event.id,
      event.privateResponsePolicy.policyHash
    );
    return current ? withRevealedGuestStates(db, event, current) : { status: "pending" };
  }
  if (resolution.status !== "pending") {
    return withRevealedGuestStates(db, event, resolution);
  }
  if (nowIso < event.rsvpDeadline) {
    return resolution;
  }
  if (getEvaluatorTransport(bindings) === "client_relay") {
    return resolution;
  }
  const leaseId = await acquireEvaluationLease(
    db,
    event.id,
    event.privateResponsePolicy.policyHash,
    nowIso
  );
  if (!leaseId) {
    const current = await loadResolutionRow(db, event.id);
    return withRevealedGuestStates(
      db,
      event,
      parseStoredResolution(
        current,
        event.id,
        event.privateResponsePolicy.policyHash
      )
    );
  }
  try {
    const facts = await canonicalPolicyFacts(
      bindings,
      event,
      event.privateResponsePolicy
    );
    const { batchHash, revealAttendance, slots } = await buildEvaluatorBatch(
      db,
      bindings,
      event,
      event.privateResponsePolicy,
      facts,
      nowIso
    );
    const evaluatorResult = await callEvaluator(
      bindings,
      event,
      event.privateResponsePolicy,
      facts,
      batchHash,
      revealAttendance,
      slots
    );
    const resolvedAt = (/* @__PURE__ */ new Date()).toISOString();
    const attendingMemberIds = evaluatorResult.status === "confirmed" && evaluatorResult.revealAttendance ? JSON.stringify(evaluatorResult.attendingMemberIds) : null;
    await db.prepare(
      `UPDATE event_resolutions
         SET status = ?,
             batch_hash = ?,
             attending_member_ids = ?,
             resolved_at = ?,
             evaluation_lease_id = NULL,
             evaluation_lease_expires_at = NULL,
             updated_at = ?
         WHERE event_id = ?
           AND policy_hash = ?
           AND status = 'evaluating'
           AND evaluation_lease_id = ?`
    ).bind(
      evaluatorResult.status,
      batchHash,
      attendingMemberIds,
      resolvedAt,
      resolvedAt,
      event.id,
      event.privateResponsePolicy.policyHash,
      leaseId
    ).run();
    await db.prepare(
      `UPDATE ballot_evaluation_runs
       SET status = ?, attending_member_ids = NULL, error_code = NULL
       WHERE event_id = ? AND input_digest = ?`
    ).bind(evaluatorResult.status, event.id, batchHash).run();
    const persisted = await loadResolutionRow(db, event.id);
    if (!persisted) {
      throw new ApiError(
        500,
        "event_resolution_unavailable",
        "The private event result could not be saved."
      );
    }
    try {
      await sendResolutionTransitionNotifications(
        db,
        bindings,
        event,
        batchHash,
        evaluatorResult.status
      );
    } catch (error) {
      reportEvaluationFailure(event.id, error);
    }
    return withRevealedGuestStates(
      db,
      event,
      parseStoredResolution(
        persisted,
        event.id,
        event.privateResponsePolicy.policyHash
      )
    );
  } catch (error) {
    try {
      await resetEvaluationLease(
        db,
        event.id,
        event.privateResponsePolicy.policyHash,
        leaseId
      );
    } catch {
      const resetError = new ApiError(
        503,
        "evaluation_lease_reset_failed",
        "The private event result is temporarily unavailable."
      );
      reportEvaluationFailure(event.id, resetError);
      return { status: "pending", retrying: true };
    }
    reportEvaluationFailure(event.id, error);
    if (error instanceof ApiError && ["event_policy_corrupt", "event_resolution_corrupt"].includes(error.code)) {
      throw error;
    }
    return { status: "pending", retrying: true };
  }
}
async function attachEventResolutions(db, bindings, events) {
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  return Promise.all(
    events.map(async (event) => {
      try {
        let resolution = await getEventResolutionForRead(
          db,
          bindings,
          event,
          nowIso
        );
        if (resolution?.status === "pending" && getEvaluatorTransport(bindings) === "client_relay" && event.role === "host") {
          resolution = { ...resolution, relayNeeded: true };
        }
        return {
          ...event,
          resolution
        };
      } catch (error) {
        if (error instanceof ApiError && ["event_policy_corrupt", "event_resolution_corrupt"].includes(
          error.code
        )) {
          reportEvaluationFailure(event.id, error);
          return {
            ...event,
            resolution: { status: "verification_unavailable" }
          };
        }
        if (error instanceof ApiError && [
          "event_evaluation_unavailable",
          "invalid_evaluator_response",
          "server_misconfigured"
        ].includes(error.code)) {
          return {
            ...event,
            resolution: event.invitationsSent && event.privateResponsePolicy ? { status: "pending", retrying: true } : null
          };
        }
        throw error;
      }
    })
  );
}
export {
  attachEventResolutions,
  completeClientRelayEvaluation,
  getEventResolutionForRead,
  prepareInsertPendingEventResolution,
  releaseClientRelayEvaluationLease,
  startClientRelayEvaluation
};
