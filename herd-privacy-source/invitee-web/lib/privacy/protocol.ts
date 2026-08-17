export const PRIVATE_RESPONSE_PROTOCOL_VERSION = 1 as const;

export function publicRuntimeValue(key: string): string | undefined {
  if (typeof window !== "undefined") {
    return (window as Window & {
      __HERD_PUBLIC_RUNTIME_CONFIG__?: Record<string, string>;
    }).__HERD_PUBLIC_RUNTIME_CONFIG__?.[key];
  }
  return process.env[`NEXT_PUBLIC_${key}`];
}
export const PRIVATE_RESPONSE_CIPHER_SUITE =
  "P256_HKDF_SHA256_AES256_GCM" as const;

export const PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES = 4_096;
export const PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES = 4_124;
export const PRIVATE_RESPONSE_USER_WRAP_BYTES = 60;
export const PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES = 157;
export const PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN =
  "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1" as const;
export const PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN =
  "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1" as const;
export const PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN =
  "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1" as const;
export const PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN =
  "HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1" as const;
export const PRIVATE_RESPONSE_LOG_ENTRY_HASH_DOMAIN =
  "HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1" as const;
export const PRIVATE_RESPONSE_AUTHORIZATION_DOMAIN =
  "HERD-RESPONSE-AUTHORIZATION-V1" as const;
export const PRIVATE_RESPONSE_SIGNING_DERIVATION_LABEL =
  "HERD-RESPONSE-SIGNING-SEED-V1" as const;
export const PRIVATE_RESPONSE_SIGNATURE_BYTES = 64;
export const PRIVATE_RESPONSE_HASH_BYTES = 32;
export const PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES = 32;
export const PRIVATE_RESPONSE_LOG_ID = "herd-response-log-v1" as const;

export type PrivateResponseCipherSuite =
  typeof PRIVATE_RESPONSE_CIPHER_SUITE;

export type PrivateResponsePolicyV1 = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  cipherSuite: PrivateResponseCipherSuite;
  policyHash: string;
  canonicalDocument: string;
  evaluatorKeyId: string;
  evaluatorPublicKey: string;
  evaluatorMeasurement: string;
  releaseId: string;
  paddedPlaintextBytes: typeof PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES;
  frozenAt: string;
  policySigningKeyId: string | null;
  policySignature: string | null;
};

export type PrivateResponseDraftV1 = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  eventId: string;
  inviteeId: string;
  policyHash: string;
  envelopeId: string;
  accountKeyEpochId: string;
  revision: number;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: { id: string; memberIDs: string[] }[];
  nonce: string;
};

export type PrivateResponseEnvelopeV1 = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  cipherSuite: PrivateResponseCipherSuite;
  envelopeId: string;
  eventId: string;
  inviteeId: string;
  policyHash: string;
  revision: number;
  accountKeyEpochId: string;
  evaluatorKeyId: string;
  payloadCiphertext: string;
  userKeyWrap: string;
  evaluatorKeyWrap: string;
  responseSigningPublicKey: string;
  responseSignature: string;
};

export type PrivateResponseUnsignedEnvelopeV1 = Omit<
  PrivateResponseEnvelopeV1,
  "responseSignature"
>;

export type StoredPrivateResponseEnvelopeV1 = PrivateResponseEnvelopeV1 & {
  ciphertextHash: string;
  createdAt: string;
  updatedAt: string;
};

export type PrivateResponseLogHeadV1 = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  logId: string;
  treeSize: number;
  headEntryHash: string;
  generatedAt: string;
  signingKeyId: string;
  signature: string;
};

export type PrivateResponseTransparencyProofV1 = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  logId: string;
  logIndex: number;
  previousEntryHash: string;
  entryHash: string;
  signingKeyId: string;
  receiptSignature: string;
  logHead: PrivateResponseLogHeadV1;
};

export type PrivateResponseReceiptV1 = {
  envelopeId: string;
  eventId: string;
  inviteeId: string;
  policyHash: string;
  accountKeyEpochId: string;
  revision: number;
  ciphertextHash: string;
  responseSigningPublicKey: string;
  responseSignature: string;
  committedAt: string;
  transparency: PrivateResponseTransparencyProofV1 | null;
};

export type PrivateResponseReceiptCoreV1 = Omit<
  PrivateResponseReceiptV1,
  "transparency"
>;

export function canonicalPrivateResponseLogEntryCore(
  receipt: PrivateResponseReceiptCoreV1,
  proof: Pick<
    PrivateResponseTransparencyProofV1,
    "protocolVersion" | "logId" | "logIndex" | "previousEntryHash"
  >,
): string {
  return JSON.stringify({
    protocolVersion: proof.protocolVersion,
    logId: proof.logId,
    logIndex: proof.logIndex,
    previousEntryHash: proof.previousEntryHash,
    envelopeId: receipt.envelopeId,
    eventId: receipt.eventId,
    inviteeId: receipt.inviteeId,
    policyHash: receipt.policyHash,
    accountKeyEpochId: receipt.accountKeyEpochId,
    revision: receipt.revision,
    ciphertextHash: receipt.ciphertextHash,
    responseSigningPublicKey: receipt.responseSigningPublicKey,
    responseSignature: receipt.responseSignature,
    committedAt: receipt.committedAt,
  });
}

export function canonicalPrivateResponseReceiptPayload(
  receipt: PrivateResponseReceiptCoreV1,
  proof: Pick<
    PrivateResponseTransparencyProofV1,
    | "protocolVersion"
    | "logId"
    | "logIndex"
    | "previousEntryHash"
    | "entryHash"
    | "signingKeyId"
  >,
): string {
  return JSON.stringify({
    protocolVersion: proof.protocolVersion,
    logId: proof.logId,
    logIndex: proof.logIndex,
    previousEntryHash: proof.previousEntryHash,
    entryHash: proof.entryHash,
    envelopeId: receipt.envelopeId,
    eventId: receipt.eventId,
    inviteeId: receipt.inviteeId,
    policyHash: receipt.policyHash,
    accountKeyEpochId: receipt.accountKeyEpochId,
    revision: receipt.revision,
    ciphertextHash: receipt.ciphertextHash,
    responseSigningPublicKey: receipt.responseSigningPublicKey,
    responseSignature: receipt.responseSignature,
    committedAt: receipt.committedAt,
    signingKeyId: proof.signingKeyId,
  });
}

export function canonicalPrivateResponseLogHeadPayload(
  head: Omit<PrivateResponseLogHeadV1, "signature">,
): string {
  return JSON.stringify({
    protocolVersion: head.protocolVersion,
    logId: head.logId,
    treeSize: head.treeSize,
    headEntryHash: head.headEntryHash,
    generatedAt: head.generatedAt,
    signingKeyId: head.signingKeyId,
  });
}

export function domainSeparatedUtf8(domain: string, canonicalPayload: string): Uint8Array {
  return new TextEncoder().encode(`${domain}\0${canonicalPayload}`);
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const POLICY_HASH_BYTES = 32;
const EVALUATOR_PUBLIC_KEY_BYTES = 65;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function requireExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  field: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError(`${field} contains unsupported fields.`);
  }
}

function requireUuid(value: unknown, field: string): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError(`${field} must be a UUID.`);
  }
  return value.toLowerCase();
}

function requireInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 1_000_000) {
    throw new TypeError(`${field} must be a positive integer.`);
  }
  return value as number;
}

function requireKeyId(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 120 ||
    !/^[A-Za-z0-9._-]+$/.test(value)
  ) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}

function requireCanonicalTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a canonical timestamp.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError(`${field} must be a canonical timestamp.`);
  }
  return value;
}

export function base64UrlDecodedLength(value: string): number {
  if (!value || !BASE64URL_PATTERN.test(value) || value.includes("=")) return -1;
  const remainder = value.length % 4;
  if (remainder === 1) return -1;
  return Math.floor((value.length * 6) / 8);
}

function requireBase64UrlBytes(
  value: unknown,
  field: string,
  expectedBytes: number,
): string {
  if (typeof value !== "string" || base64UrlDecodedLength(value) !== expectedBytes) {
    throw new TypeError(`${field} must encode exactly ${expectedBytes} bytes.`);
  }
  const decoded = base64UrlToBytes(value);
  if (decoded.length !== expectedBytes || bytesToBase64Url(decoded) !== value) {
    throw new TypeError(`${field} must use canonical unpadded base64url.`);
  }
  return value;
}

export function normalizePrivateResponseUnsignedEnvelope(
  value: unknown,
): PrivateResponseUnsignedEnvelopeV1 {
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
    ],
    "envelope",
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
      POLICY_HASH_BYTES,
    ),
    revision: requireInteger(value.revision, "envelope.revision"),
    accountKeyEpochId: requireUuid(
      value.accountKeyEpochId,
      "envelope.accountKeyEpochId",
    ),
    evaluatorKeyId: requireKeyId(
      value.evaluatorKeyId,
      "envelope.evaluatorKeyId",
    ),
    payloadCiphertext: requireBase64UrlBytes(
      value.payloadCiphertext,
      "envelope.payloadCiphertext",
      PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES,
    ),
    userKeyWrap: requireBase64UrlBytes(
      value.userKeyWrap,
      "envelope.userKeyWrap",
      PRIVATE_RESPONSE_USER_WRAP_BYTES,
    ),
    evaluatorKeyWrap: requireBase64UrlBytes(
      value.evaluatorKeyWrap,
      "envelope.evaluatorKeyWrap",
      PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES,
    ),
    responseSigningPublicKey: requireBase64UrlBytes(
      value.responseSigningPublicKey,
      "envelope.responseSigningPublicKey",
      PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES,
    ),
  };
}

export function normalizePrivateResponseEnvelope(
  value: unknown,
): PrivateResponseEnvelopeV1 {
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
      "responseSignature",
    ],
    "envelope",
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
      PRIVATE_RESPONSE_SIGNATURE_BYTES,
    ),
  };
}

export function normalizeStoredPrivateResponseEnvelope(
  value: unknown,
): StoredPrivateResponseEnvelopeV1 {
  if (!isRecord(value)) throw new TypeError("stored envelope must be an object.");
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
      "responseSignature",
      "ciphertextHash",
      "createdAt",
      "updatedAt",
    ],
    "stored envelope",
  );
  const {
    ciphertextHash,
    createdAt,
    updatedAt,
    ...envelope
  } = value;
  return {
    ...normalizePrivateResponseEnvelope(envelope),
    ciphertextHash: requireBase64UrlBytes(
      ciphertextHash,
      "stored envelope.ciphertextHash",
      PRIVATE_RESPONSE_HASH_BYTES,
    ),
    createdAt: requireCanonicalTimestamp(createdAt, "stored envelope.createdAt"),
    updatedAt: requireCanonicalTimestamp(updatedAt, "stored envelope.updatedAt"),
  };
}

export function normalizeEvaluatorPublicKey(value: unknown): string {
  const normalized = requireBase64UrlBytes(
    value,
    "evaluatorPublicKey",
    EVALUATOR_PUBLIC_KEY_BYTES,
  );
  if (base64UrlToBytes(normalized)[0] !== 0x04) {
    throw new TypeError("evaluatorPublicKey must be an uncompressed P-256 point.");
  }
  return normalized;
}

export function canonicalEnvelopeJson(
  envelope: PrivateResponseEnvelopeV1 | PrivateResponseUnsignedEnvelopeV1,
): string {
  const { responseSignature: _responseSignature, ...unsigned } = envelope as PrivateResponseEnvelopeV1;
  void _responseSignature;
  return JSON.stringify(normalizePrivateResponseUnsignedEnvelope(unsigned));
}

export function canonicalPrivateResponseAuthorizationPayload(
  envelope: PrivateResponseEnvelopeV1 | PrivateResponseUnsignedEnvelopeV1,
  ciphertextHash: string,
): string {
  const normalized = normalizePrivateResponseUnsignedEnvelope(
    Object.fromEntries(
      Object.entries(envelope).filter(([key]) => key !== "responseSignature"),
    ),
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
      PRIVATE_RESPONSE_HASH_BYTES,
    ),
    responseSigningPublicKey: normalized.responseSigningPublicKey,
  });
}

export function privateResponseAuthorizationBytes(
  envelope: PrivateResponseEnvelopeV1 | PrivateResponseUnsignedEnvelopeV1,
  ciphertextHash: string,
): Uint8Array {
  return domainSeparatedUtf8(
    PRIVATE_RESPONSE_AUTHORIZATION_DOMAIN,
    canonicalPrivateResponseAuthorizationPayload(envelope, ciphertextHash),
  );
}

/**
 * Verifies that the envelope's advertised Ed25519 identity authorized its
 * exact unsigned ciphertext commitment. This does not establish first-write
 * ownership; the independent authority pins that identity on revision one.
 */
export async function verifyPrivateResponseAuthorizationSignature(
  envelope: PrivateResponseEnvelopeV1,
  ciphertextHash: string,
): Promise<boolean> {
  try {
    const normalized = normalizePrivateResponseEnvelope(envelope);
    const publicKey = await globalThis.crypto.subtle.importKey(
      "raw",
      Uint8Array.from(
        base64UrlToBytes(normalized.responseSigningPublicKey),
      ).buffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      Uint8Array.from(base64UrlToBytes(normalized.responseSignature)).buffer,
      Uint8Array.from(
        privateResponseAuthorizationBytes(normalized, ciphertextHash),
      ).buffer,
    );
  } catch {
    return false;
  }
}

export function privateResponseContext(
  envelope: Pick<
    PrivateResponseEnvelopeV1,
    "eventId" | "inviteeId" | "policyHash" | "envelopeId" | "accountKeyEpochId" | "revision"
  >,
): Uint8Array {
  const result = new Uint8Array(101);
  let offset = 0;
  result[offset] = PRIVATE_RESPONSE_PROTOCOL_VERSION;
  offset += 1;
  for (const value of [
    uuidToBytes(envelope.eventId),
    uuidToBytes(envelope.inviteeId),
    base64UrlToBytes(envelope.policyHash),
    uuidToBytes(envelope.envelopeId),
    uuidToBytes(envelope.accountKeyEpochId),
  ]) {
    result.set(value, offset);
    offset += value.length;
  }
  new DataView(result.buffer).setUint32(offset, envelope.revision, false);
  return result;
}

export function privateResponseAad(
  purpose:
    | "payload"
    | "user-key-wrap"
    | "evaluator-key-wrap"
    | "user-key-derivation"
    | "evaluator-key-derivation",
  envelope: Pick<
    PrivateResponseEnvelopeV1,
    "eventId" | "inviteeId" | "policyHash" | "envelopeId" | "accountKeyEpochId" | "revision"
  >,
): Uint8Array {
  const labels = {
    payload: "HERD-RSVP-PAYLOAD-AAD-V1",
    "user-key-wrap": "HERD-RSVP-USER-WRAP-AAD-V1",
    "evaluator-key-wrap": "HERD-RSVP-EVALUATOR-WRAP-AAD-V1",
    "user-key-derivation": "HERD-RSVP-USER-KEK-V1",
    "evaluator-key-derivation": "HERD-RSVP-EVALUATOR-KEK-V1",
  } as const;
  return concatenateBytes(
    new TextEncoder().encode(labels[purpose]),
    new Uint8Array([0]),
    privateResponseContext(envelope),
  );
}

export function uuidToBytes(value: string): Uint8Array {
  const normalized = requireUuid(value, "UUID").replaceAll("-", "");
  const bytes = new Uint8Array(16);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function base64UrlToBytes(value: string): Uint8Array {
  if (base64UrlDecodedLength(value) < 0) throw new TypeError("Invalid base64url value.");
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function bytesToBase64Url(value: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < value.length; index += 0x8000) {
    binary += String.fromCharCode(...value.subarray(index, index + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function concatenateBytes(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}
