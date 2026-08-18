// Generated from invitee-web/lib/backend/resolutions.ts for compatibility testing; do not edit by hand.

// invitee-web/lib/privacy/protocol.ts
var PRIVATE_RESPONSE_PROTOCOL_VERSION = 1;
var PRIVATE_RESPONSE_CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM";
var PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES = 4096;
var PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES = 4124;
var PRIVATE_RESPONSE_USER_WRAP_BYTES = 60;
var PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES = 157;
var PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN = "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1";
var PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1";
var PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
var PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1";
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
function ownedArrayBuffer(value) {
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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}
async function verifyP256Signature(publicKey, domain, canonicalPayload, signature) {
  const publicKeyBytes = base64UrlToBytes(publicKey);
  const signatureBytes = base64UrlToBytes(signature);
  if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 4 || signatureBytes.length !== PRIVATE_RESPONSE_SIGNATURE_BYTES || bytesToBase64Url(signatureBytes) !== signature) {
    return false;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer(publicKeyBytes),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    ownedArrayBuffer(signatureBytes),
    ownedArrayBuffer(domainSeparatedUtf8(domain, canonicalPayload))
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
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalEnvelopeJson(envelope))
  );
  return bytesToBase64Url(new Uint8Array(digest));
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

// invitee-web/lib/backend/crypto.ts
var encoder = new TextEncoder();
function randomUuid() {
  return crypto.randomUUID();
}

// invitee-web/lib/backend/resolution-notifications.ts
var TWILIO_MESSAGES_ORIGIN = "https://api.twilio.com";
var DISPATCH_TIMEOUT_MILLISECONDS = 1e4;
function messageBody(title, status) {
  return status === "confirmed" ? `Herd: ${title} is confirmed. Replies can still change; guest statuses stay private until the deadline.` : `Herd: ${title} is no longer confirmed. Replies can still change.`;
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
    `SELECT users.phone_number AS phoneNumber
       FROM events
       JOIN users ON users.id = events.host_user_id
       WHERE events.id = ?
       UNION
       SELECT invitees.phone_number AS phoneNumber
       FROM invitees
       WHERE invitees.event_id = ?
         AND EXISTS (
           SELECT 1 FROM response_envelopes
           WHERE response_envelopes.invitee_id = invitees.id
         )
       ORDER BY phoneNumber ASC`
  ).bind(event.id, event.id).all();
  const config = getInvitationDeliveryConfig(bindings);
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  for (const recipient of recipients.results) {
    const id = randomUuid();
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
            Body: messageBody(event.title || "Your event", status)
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
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return bytesToBase64Url(new Uint8Array(digest));
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
    if (!isCanonicalBase64UrlBytes(row.batchHash, 32) || !row.resolvedAt || !Number.isFinite(Date.parse(row.resolvedAt)) || row.evaluationLeaseId || row.evaluationLeaseExpiresAt || row.evaluationRequestHash !== null && !isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32)) {
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
function requiresDeadlineReveal(row, event, nowIso) {
  return Boolean(
    event.rsvpDeadline && nowIso >= event.rsvpDeadline && (row.status === "confirmed" || row.status === "not_confirmed") && row.resolvedAt && row.resolvedAt < event.rsvpDeadline
  );
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
async function resetResolvedForReevaluation(db, eventId, policyHash, nowIso) {
  await db.prepare(
    `UPDATE event_resolutions
       SET status = 'pending',
           batch_hash = NULL,
           attending_member_ids = NULL,
           resolved_at = NULL,
           evaluation_lease_id = NULL,
           evaluation_lease_expires_at = NULL,
           evaluation_request_hash = NULL,
           result_attestation_protocol_version = NULL,
           result_attestation_signing_key_id = NULL,
           result_attestation_evaluated_at = NULL,
           result_attestation_canonical_document = NULL,
           result_attestation_signature = NULL,
           updated_at = ?
       WHERE event_id = ? AND policy_hash = ?`
  ).bind(nowIso, eventId, policyHash).run();
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
  const row = await loadResolutionRow(db, eventId);
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
  const slots = facts.inviteeIds.map((inviteeId) => {
    const response = latest.get(inviteeId);
    if (!response) return { inviteeId, envelopeHash: null, envelope: null };
    const { ciphertextHash, ...envelope } = response;
    return { inviteeId, envelopeHash: ciphertextHash, envelope };
  });
  const revealAttendance = nowIso >= event.rsvpDeadline;
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
  return {
    batchHash: await sha256Base64Url2(batchDocument),
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
function ownedArrayBuffer2(value) {
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
      ownedArrayBuffer2(base64UrlToBytes(evaluatorPublicKey2)),
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
    ownedArrayBuffer2(sharedSecret),
    "HKDF",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: ownedArrayBuffer2(saltBytes),
      info: ownedArrayBuffer2(
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
        iv: ownedArrayBuffer2(iv),
        additionalData: ownedArrayBuffer2(
          concatenateBytes(utf8(RELAY_AAD_LABEL), utf8(context))
        ),
        tagLength: 128
      },
      aesKey,
      ownedArrayBuffer2(plaintext)
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
    ownedArrayBuffer2(utf8(capabilityToken)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const capabilityMac = bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        capabilityKey,
        ownedArrayBuffer2(
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
       SET status = 'evaluating',
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
       SET status = 'pending',
           batch_hash = NULL,
           evaluation_request_hash = NULL,
           evaluation_lease_id = NULL,
           evaluation_lease_expires_at = NULL,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND status = 'evaluating'
         AND evaluation_lease_id = ?`
  ).bind(nowIso, eventId, policyHash, leaseId).run();
  return (released.meta.changes ?? 0) === 1;
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
  let row = await ensurePendingResolution(
    db,
    event.id,
    policy.policyHash,
    nowIso
  );
  if (requiresDeadlineReveal(row, event, nowIso)) {
    await resetResolvedForReevaluation(db, event.id, policy.policyHash, nowIso);
    row = await loadResolutionRow(db, event.id);
  }
  const existing = parseStoredResolution(row, event.id, policy.policyHash);
  if (existing.status !== "pending") {
    return { kind: "resolved", resolution: existing };
  }
  if (row.status === "evaluating" && row.evaluationLeaseExpiresAt && row.evaluationLeaseExpiresAt > nowIso) {
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
  if (existing.status !== "pending") return existing;
  if (row.status !== "evaluating" || !row.batchHash || !row.evaluationRequestHash || !row.evaluationLeaseId || !row.evaluationLeaseExpiresAt || row.evaluationLeaseExpiresAt <= nowIso) {
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
  if (evaluatorResult.revealAttendance !== evaluatedAt >= event.rsvpDeadline || evaluatedAt > row.evaluationLeaseExpiresAt || Date.parse(evaluatedAt) > Date.parse(nowIso) + 3e4) {
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
      ownedArrayBuffer2(base64UrlToBytes(relay.resultSigningPublicKey)),
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
      ownedArrayBuffer2(base64UrlToBytes(attestation.signature)),
      ownedArrayBuffer2(utf8(canonicalDocument))
    );
  } catch {
    invalidRelayAttestation();
  }
  if (!verified) invalidRelayAttestation();
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
         AND status = 'evaluating'
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
  if (!event.invitationsSent || !event.privateResponsePolicy) return null;
  if (!event.rsvpDeadline) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "A sent event is missing its reply deadline."
    );
  }
  let row = await ensurePendingResolution(
    db,
    event.id,
    event.privateResponsePolicy.policyHash,
    nowIso
  );
  if (requiresDeadlineReveal(row, event, nowIso)) {
    await resetResolvedForReevaluation(
      db,
      event.id,
      event.privateResponsePolicy.policyHash,
      nowIso
    );
    row = await loadResolutionRow(db, event.id);
  }
  const resolution = parseStoredResolution(
    row,
    event.id,
    event.privateResponsePolicy.policyHash
  );
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
