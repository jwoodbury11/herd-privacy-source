import {
  PRIVATE_RESPONSE_CIPHER_SUITE,
  PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES,
  PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES,
  PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  PRIVATE_RESPONSE_SIGNING_DERIVATION_LABEL,
  PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES,
  PRIVATE_RESPONSE_USER_WRAP_BYTES,
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalEnvelopeJson,
  concatenateBytes,
  normalizeEvaluatorPublicKey,
  normalizePrivateResponseEnvelope,
  normalizePrivateResponseUnsignedEnvelope,
  normalizeStoredPrivateResponseEnvelope,
  privateResponseAad,
  privateResponseAuthorizationBytes,
  publicRuntimeValue,
  uuidToBytes,
  type PrivateResponseDraftV1,
  type PrivateResponseEnvelopeV1,
  type PrivateResponsePolicyV1,
  type StoredPrivateResponseEnvelopeV1,
} from "./protocol";
import {
  configuredPolicySigningPin,
  verifyEventPolicyCertification,
} from "./trust-verification";

const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BITS = 128;
const RESPONSE_KEY_BYTES = 32;
const POLICY_HASH_BYTES = 32;
const EVALUATOR_PUBLIC_KEY_BYTES = 65;
const EVALUATOR_SALT_BYTES = 32;
const DRAFT_NONCE_BYTES = 16;
const MAX_PARTICIPANTS = 20;
const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const bakedEvaluatorKeyId = publicRuntimeValue("HERD_EVALUATOR_KEY_ID");
const bakedEvaluatorPublicKey = publicRuntimeValue("HERD_EVALUATOR_PUBLIC_KEY");

export class PrivateResponseCryptoError extends Error {
  readonly canSwitchDevice: boolean;

  constructor(message: string, options: { canSwitchDevice?: boolean } = {}) {
    super(message);
    this.name = "PrivateResponseCryptoError";
    this.canSwitchDevice = options.canSwitchDevice ?? false;
  }
}

export type SealPrivateResponseInput = {
  eventId: string;
  inviteeId: string;
  accountKeyEpochId: string;
  revision: number;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: { id: string; memberIDs: string[] }[];
  allowedInviteeIds: string[];
  accountRootSecret: Uint8Array;
  policy: PrivateResponsePolicyV1;
};

export type OpenPrivateResponseInput = {
  envelope: PrivateResponseEnvelopeV1 | StoredPrivateResponseEnvelopeV1;
  eventId: string;
  inviteeId: string;
  allowedInviteeIds: string[];
  accountRootSecret: Uint8Array;
  policy: PrivateResponsePolicyV1;
};

type TrustedFrozenPolicy = {
  evaluatorKeyId: string;
  evaluatorPublicKey: Uint8Array;
  eventId: string;
  inviteeIds: string[];
  hostMinimumParticipants: number;
  maximumParticipants: number;
};

function cryptoApi(): Crypto {
  const value = globalThis.crypto;
  if (!value?.subtle || typeof value.getRandomValues !== "function") {
    throw new PrivateResponseCryptoError(
      "Private responses require a browser with Web Crypto support.",
    );
  }
  return value;
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;
}

function randomBytes(length: number): Uint8Array {
  return cryptoApi().getRandomValues(new Uint8Array(length));
}

function randomUuid(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function strictBase64UrlBytes(
  value: string,
  expectedLength: number,
  field: string,
): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(value);
  } catch {
    throw new PrivateResponseCryptoError(`${field} is not valid base64url.`);
  }
  if (
    bytes.length !== expectedLength ||
    bytesToBase64Url(bytes) !== value
  ) {
    throw new PrivateResponseCryptoError(
      `${field} must be canonical base64url for ${expectedLength} bytes.`,
    );
  }
  return bytes;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PrivateResponseCryptoError(`${field} is invalid.`);
  }
  return value as Record<string, unknown>;
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
    throw new PrivateResponseCryptoError(`${field} contains unsupported fields.`);
  }
}

function normalizeUuid(value: unknown, field: string): string {
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

function boundedInteger(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new PrivateResponseCryptoError(
      `${field} must be an integer from ${minimum} to ${maximum}.`,
    );
  }
  return value as number;
}

function normalizeDraft(
  value: unknown,
  allowedInviteeIds: string[],
  frozenPolicy: TrustedFrozenPolicy,
): PrivateResponseDraftV1 {
  const input = requireRecord(value, "Private response");
  requireExactKeys(
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
      "nonce",
    ],
    "Private response",
  );
  if (input.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION) {
    throw new PrivateResponseCryptoError("The private-response version is unsupported.");
  }
  const eventId = normalizeUuid(input.eventId, "eventId");
  const inviteeId = normalizeUuid(input.inviteeId, "inviteeId");
  const envelopeId = normalizeUuid(input.envelopeId, "envelopeId");
  const accountKeyEpochId = normalizeUuid(
    input.accountKeyEpochId,
    "accountKeyEpochId",
  );
  if (typeof input.policyHash !== "string") {
    throw new PrivateResponseCryptoError("policyHash is invalid.");
  }
  strictBase64UrlBytes(input.policyHash, POLICY_HASH_BYTES, "policyHash");
  if (
    !Number.isInteger(input.revision) ||
    (input.revision as number) < 1 ||
    (input.revision as number) > 1_000_000
  ) {
    throw new PrivateResponseCryptoError("revision is invalid.");
  }
  if (input.response !== "going" && input.response !== "cant_commit") {
    throw new PrivateResponseCryptoError("response is invalid.");
  }
  const minimumParticipants = input.minimumParticipants;
  if (input.response === "going") {
    if (!Number.isInteger(minimumParticipants)) {
      throw new PrivateResponseCryptoError(
        "A going response must include an integer minimum participant count.",
      );
    }
    if ((minimumParticipants as number) < frozenPolicy.hostMinimumParticipants) {
      throw new PrivateResponseCryptoError(
        "The response minimum cannot be below the frozen host minimum.",
      );
    }
    if ((minimumParticipants as number) > frozenPolicy.maximumParticipants) {
      throw new PrivateResponseCryptoError(
        "The response minimum cannot exceed the frozen participant maximum.",
      );
    }
  }
  if (!Array.isArray(input.requiredGroups) || input.requiredGroups.length > MAX_PARTICIPANTS) {
    throw new PrivateResponseCryptoError("requiredGroups is invalid.");
  }
  if (!Array.isArray(allowedInviteeIds)) {
    throw new PrivateResponseCryptoError("allowedInviteeIds is invalid.");
  }
  const normalizedAllowedInviteeIds = allowedInviteeIds.map((id, index) =>
    normalizeUuid(id, `allowedInviteeIds[${index}]`),
  );
  const allowed = new Set(normalizedAllowedInviteeIds);
  const frozenInvitees = new Set(frozenPolicy.inviteeIds);
  if (
    allowed.size !== normalizedAllowedInviteeIds.length ||
    allowed.size + 1 !== frozenPolicy.maximumParticipants ||
    allowed.size !== frozenInvitees.size ||
    normalizedAllowedInviteeIds.some((id) => !frozenInvitees.has(id))
  ) {
    throw new PrivateResponseCryptoError(
      "The invited people do not match the frozen event policy.",
    );
  }
  if (eventId !== frozenPolicy.eventId) {
    throw new PrivateResponseCryptoError(
      "The response event does not match the frozen event policy.",
    );
  }
  if (!allowed.has(inviteeId)) {
    throw new PrivateResponseCryptoError(
      "The respondent is not in the frozen event policy.",
    );
  }
  const seenMembers = new Set<string>();
  const seenGroups = new Set<string>();
  const requiredGroups = input.requiredGroups.map((rawGroup, groupIndex) => {
    const group = requireRecord(rawGroup, `requiredGroups[${groupIndex}]`);
    requireExactKeys(group, ["id", "memberIDs"], `requiredGroups[${groupIndex}]`);
    const id = normalizeUuid(group.id, `requiredGroups[${groupIndex}].id`);
    if (seenGroups.has(id)) {
      throw new PrivateResponseCryptoError("Condition group IDs must be unique.");
    }
    seenGroups.add(id);
    if (
      !Array.isArray(group.memberIDs) ||
      group.memberIDs.length < 1 ||
      group.memberIDs.length > MAX_PARTICIPANTS
    ) {
      throw new PrivateResponseCryptoError(
        `requiredGroups[${groupIndex}].memberIDs is invalid.`,
      );
    }
    const memberIDs = group.memberIDs.map((rawMemberId, memberIndex) => {
      const memberId = normalizeUuid(
        rawMemberId,
        `requiredGroups[${groupIndex}].memberIDs[${memberIndex}]`,
      );
      if (
        memberId === inviteeId ||
        !allowed.has(memberId) ||
        seenMembers.has(memberId)
      ) {
        throw new PrivateResponseCryptoError(
          "Each condition member must be another invited person and may appear only once.",
        );
      }
      seenMembers.add(memberId);
      return memberId;
    });
    return { id, memberIDs };
  });
  if (
    input.response === "cant_commit" &&
    (minimumParticipants !== null || requiredGroups.length > 0)
  ) {
    throw new PrivateResponseCryptoError(
      "A can’t-commit response cannot contain attendance conditions.",
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
    revision: input.revision as number,
    response: input.response,
    minimumParticipants: minimumParticipants as number | null,
    requiredGroups,
    nonce: input.nonce,
  };
}

async function assertTrustedPolicy(
  policy: PrivateResponsePolicyV1,
  serverVerifiedTrust?: {
    evaluatorKeyId: string;
    evaluatorPublicKey: string;
  },
): Promise<TrustedFrozenPolicy> {
  if (
    policy.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    policy.cipherSuite !== PRIVATE_RESPONSE_CIPHER_SUITE ||
    policy.paddedPlaintextBytes !== PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES
  ) {
    throw new PrivateResponseCryptoError("This event uses an unsupported privacy policy.");
  }
  const trustedEvaluatorKeyId = serverVerifiedTrust?.evaluatorKeyId ?? bakedEvaluatorKeyId;
  const trustedEvaluatorPublicKey =
    serverVerifiedTrust?.evaluatorPublicKey ?? bakedEvaluatorPublicKey;
  if (!trustedEvaluatorKeyId || !trustedEvaluatorPublicKey) {
    throw new PrivateResponseCryptoError(
      "Private responses are unavailable because this Herd release has no trusted evaluator configured.",
    );
  }
  let evaluatorPublicKey: string;
  let expectedPublicKey: string;
  try {
    evaluatorPublicKey = normalizeEvaluatorPublicKey(policy.evaluatorPublicKey);
    expectedPublicKey = normalizeEvaluatorPublicKey(trustedEvaluatorPublicKey);
  } catch {
    throw new PrivateResponseCryptoError("The trusted evaluator key is malformed.");
  }
  const evaluatorBytes = strictBase64UrlBytes(
    evaluatorPublicKey,
    EVALUATOR_PUBLIC_KEY_BYTES,
    "evaluatorPublicKey",
  );
  const expectedBytes = strictBase64UrlBytes(
    expectedPublicKey,
    EVALUATOR_PUBLIC_KEY_BYTES,
    "trusted evaluator public key",
  );
  if (
    policy.evaluatorKeyId !== trustedEvaluatorKeyId ||
    !sameBytes(evaluatorBytes, expectedBytes)
  ) {
    throw new PrivateResponseCryptoError(
      "This event’s evaluator does not match the evaluator trusted by this Herd release.",
    );
  }
  if (evaluatorBytes[0] !== 0x04) {
    throw new PrivateResponseCryptoError(
      "The trusted evaluator key is not an uncompressed P-256 key.",
    );
  }
  const policyHash = strictBase64UrlBytes(
    policy.policyHash,
    POLICY_HASH_BYTES,
    "policyHash",
  );
  if (typeof policy.canonicalDocument !== "string" || !policy.canonicalDocument) {
    throw new PrivateResponseCryptoError("The frozen event policy is missing.");
  }
  const computedPolicyHash = new Uint8Array(
    await cryptoApi().subtle.digest(
      "SHA-256",
      toArrayBuffer(textEncoder.encode(policy.canonicalDocument)),
    ),
  );
  if (!sameBytes(policyHash, computedPolicyHash)) {
    throw new PrivateResponseCryptoError("The frozen event policy hash is invalid.");
  }
  if (!serverVerifiedTrust) {
    const policySigningPin = configuredPolicySigningPin();
    if (!policySigningPin) {
      throw new PrivateResponseCryptoError(
        "Private responses are unavailable because this Herd release has no policy-signing trust pin.",
      );
    }
    try {
      await verifyEventPolicyCertification(policy, policySigningPin);
    } catch {
      throw new PrivateResponseCryptoError(
        "The frozen event policy is not certified by this Herd release.",
      );
    }
  }

  let document: Record<string, unknown>;
  try {
    const parsed = JSON.parse(policy.canonicalDocument) as unknown;
    document = requireRecord(parsed, "Frozen event policy");
    if (JSON.stringify(parsed) !== policy.canonicalDocument) {
      throw new PrivateResponseCryptoError(
        "The frozen event policy document is not canonical JSON.",
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
    MAX_PARTICIPANTS,
  );
  if (inviteeIds.length + 1 !== maximumParticipants) {
    throw new PrivateResponseCryptoError(
      "The frozen event participant maximum does not match its member list.",
    );
  }
  const hostRules = requireRecord(document.hostRules, "Frozen event policy host rules");
  const hostMinimumParticipants = boundedInteger(
    hostRules.minimumParticipants,
    "Frozen host minimum",
    2,
    maximumParticipants,
  );
  const documentEvaluator = requireRecord(
    document.evaluator,
    "Frozen event policy evaluator",
  );
  let documentEvaluatorPublicKey: Uint8Array;
  try {
    documentEvaluatorPublicKey = strictBase64UrlBytes(
      normalizeEvaluatorPublicKey(documentEvaluator.publicKey),
      EVALUATOR_PUBLIC_KEY_BYTES,
      "Frozen event policy evaluator public key",
    );
  } catch {
    throw new PrivateResponseCryptoError(
      "The frozen event policy evaluator key is malformed.",
    );
  }
  if (
    document.protocolVersion !== policy.protocolVersion ||
    document.cipherSuite !== policy.cipherSuite ||
    limits.paddedPlaintextBytes !== policy.paddedPlaintextBytes ||
    documentEvaluator.keyId !== policy.evaluatorKeyId ||
    documentEvaluator.measurement !== policy.evaluatorMeasurement ||
    document.releaseId !== policy.releaseId ||
    !sameBytes(documentEvaluatorPublicKey, evaluatorBytes)
  ) {
    throw new PrivateResponseCryptoError(
      "The frozen event policy document does not match its trusted descriptor.",
    );
  }
  return {
    evaluatorKeyId: policy.evaluatorKeyId,
    evaluatorPublicKey: evaluatorBytes,
    eventId,
    inviteeIds,
    hostMinimumParticipants,
    maximumParticipants,
  };
}

function serializePaddedDraft(draft: PrivateResponseDraftV1): Uint8Array {
  // Property order is part of the v1 cross-platform canonical representation.
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
      memberIDs: group.memberIDs,
    })),
    nonce: draft.nonce,
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

function parsePaddedDraft(
  value: Uint8Array,
  allowedInviteeIds: string[],
  frozenPolicy: TrustedFrozenPolicy,
): PrivateResponseDraftV1 {
  if (value.length !== PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES) {
    throw new PrivateResponseCryptoError("The private response has the wrong size.");
  }
  const length = new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getUint16(0, false);
  if (length < 2 || length > value.length - 2) {
    throw new PrivateResponseCryptoError("The private response frame is invalid.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(textDecoder.decode(value.subarray(2, 2 + length)));
  } catch {
    throw new PrivateResponseCryptoError("The private response could not be decoded.");
  }
  return normalizeDraft(parsed, allowedInviteeIds, frozenPolicy);
}

async function importAesKey(rawKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (rawKey.length !== RESPONSE_KEY_BYTES) {
    throw new PrivateResponseCryptoError("A private-response key has the wrong size.");
  }
  return cryptoApi().subtle.importKey(
    "raw",
    toArrayBuffer(rawKey),
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

async function deriveHkdfAesKey(
  inputKey: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const baseKey = await cryptoApi().subtle.importKey(
    "raw",
    toArrayBuffer(inputKey),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return cryptoApi().subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(info),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

async function deriveHkdfBytes(
  inputKey: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const baseKey = await cryptoApi().subtle.importKey(
    "raw",
    toArrayBuffer(inputKey),
    "HKDF",
    false,
    ["deriveBits"],
  );
  return new Uint8Array(
    await cryptoApi().subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(info),
      },
      baseKey,
      length * 8,
    ),
  );
}

async function deriveResponseSigningKey(
  accountRootSecret: Uint8Array,
  envelope: Pick<
    PrivateResponseEnvelopeV1,
    "policyHash" | "eventId" | "inviteeId"
  >,
): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const seed = await deriveHkdfBytes(
    accountRootSecret,
    strictBase64UrlBytes(envelope.policyHash, POLICY_HASH_BYTES, "policyHash"),
    concatenateBytes(
      textEncoder.encode(PRIVATE_RESPONSE_SIGNING_DERIVATION_LABEL),
      new Uint8Array([0]),
      uuidToBytes(envelope.eventId),
      uuidToBytes(envelope.inviteeId),
    ),
    RESPONSE_KEY_BYTES,
  );
  const pkcs8 = concatenateBytes(ED25519_PKCS8_SEED_PREFIX, seed);
  try {
    const temporaryPrivateKey = await cryptoApi().subtle.importKey(
      "pkcs8",
      toArrayBuffer(pkcs8),
      { name: "Ed25519" },
      true,
      ["sign"],
    );
    const jwk = await cryptoApi().subtle.exportKey("jwk", temporaryPrivateKey);
    if (
      jwk.kty !== "OKP" ||
      jwk.crv !== "Ed25519" ||
      typeof jwk.x !== "string"
    ) {
      throw new PrivateResponseCryptoError(
        "The browser produced an invalid response-signing key.",
      );
    }
    const publicKey = strictBase64UrlBytes(
      jwk.x,
      PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES,
      "responseSigningPublicKey",
    );
    // Web Crypto has no direct seed-to-public-key operation, so the first
    // import is extractable only long enough to obtain the public component.
    // Re-import the seed as non-extractable before signing any response.
    const privateKey = await cryptoApi().subtle.importKey(
      "pkcs8",
      toArrayBuffer(pkcs8),
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    return { privateKey, publicKey };
  } catch (error) {
    if (error instanceof PrivateResponseCryptoError) throw error;
    throw new PrivateResponseCryptoError(
      "This browser cannot create the required response-authentication signature.",
    );
  } finally {
    seed.fill(0);
    pkcs8.fill(0);
  }
}

async function verifyResponseAuthorization(
  envelope: PrivateResponseEnvelopeV1,
  accountRootSecret: Uint8Array,
  ciphertextHash: string,
): Promise<void> {
  const derived = await deriveResponseSigningKey(accountRootSecret, envelope);
  const publicKey = strictBase64UrlBytes(
    envelope.responseSigningPublicKey,
    PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES,
    "responseSigningPublicKey",
  );
  if (!sameBytes(publicKey, derived.publicKey)) {
    throw new PrivateResponseCryptoError(
      "This older saved private response could not be verified.",
      { canSwitchDevice: true },
    );
  }
  let verified = false;
  try {
    const verificationKey = await cryptoApi().subtle.importKey(
      "raw",
      toArrayBuffer(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    verified = await cryptoApi().subtle.verify(
      { name: "Ed25519" },
      verificationKey,
      toArrayBuffer(
        strictBase64UrlBytes(
          envelope.responseSignature,
          64,
          "responseSignature",
        ),
      ),
      toArrayBuffer(privateResponseAuthorizationBytes(envelope, ciphertextHash)),
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    throw new PrivateResponseCryptoError(
      "The saved private response has an invalid device authorization.",
      { canSwitchDevice: true },
    );
  }
}

async function aesGcmSeal(
  key: CryptoKey,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  const iv = randomBytes(AES_GCM_NONCE_BYTES);
  const ciphertextAndTag = new Uint8Array(
    await cryptoApi().subtle.encrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        additionalData: toArrayBuffer(additionalData),
        tagLength: AES_GCM_TAG_BITS,
      },
      key,
      toArrayBuffer(plaintext),
    ),
  );
  return concatenateBytes(iv, ciphertextAndTag);
}

async function aesGcmOpen(
  key: CryptoKey,
  frame: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  if (frame.length < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BITS / 8) {
    throw new PrivateResponseCryptoError("An encrypted frame is truncated.");
  }
  const iv = frame.subarray(0, AES_GCM_NONCE_BYTES);
  const ciphertextAndTag = frame.subarray(AES_GCM_NONCE_BYTES);
  try {
    return new Uint8Array(
      await cryptoApi().subtle.decrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(additionalData),
          tagLength: AES_GCM_TAG_BITS,
        },
        key,
        toArrayBuffer(ciphertextAndTag),
      ),
    );
  } catch {
    throw new PrivateResponseCryptoError(
      "This device could not authenticate the saved private response.",
      { canSwitchDevice: true },
    );
  }
}

function assertDraftMatchesEnvelope(
  draft: PrivateResponseDraftV1,
  envelope: PrivateResponseEnvelopeV1,
): void {
  if (
    draft.protocolVersion !== envelope.protocolVersion ||
    draft.eventId !== envelope.eventId ||
    draft.inviteeId !== envelope.inviteeId ||
    draft.policyHash !== envelope.policyHash ||
    draft.envelopeId !== envelope.envelopeId ||
    draft.accountKeyEpochId !== envelope.accountKeyEpochId ||
    draft.revision !== envelope.revision
  ) {
    throw new PrivateResponseCryptoError(
      "The saved private response does not match its authenticated envelope.",
    );
  }
}

function normalizeEnvelopeCore(
  value: PrivateResponseEnvelopeV1 | StoredPrivateResponseEnvelopeV1,
): { envelope: PrivateResponseEnvelopeV1; storedCiphertextHash: string | null } {
  if (
    Object.prototype.hasOwnProperty.call(value, "ciphertextHash") ||
    Object.prototype.hasOwnProperty.call(value, "createdAt") ||
    Object.prototype.hasOwnProperty.call(value, "updatedAt")
  ) {
    const stored = normalizeStoredPrivateResponseEnvelope(value);
    const {
      ciphertextHash,
      createdAt: _createdAt,
      updatedAt: _updatedAt,
      ...envelope
    } = stored;
    void _createdAt;
    void _updatedAt;
    return { envelope, storedCiphertextHash: ciphertextHash };
  }
  return {
    envelope: normalizePrivateResponseEnvelope(value),
    storedCiphertextHash: null,
  };
}

export async function sealPrivateResponse(
  input: SealPrivateResponseInput,
  serverVerifiedTrust?: {
    evaluatorKeyId: string;
    evaluatorPublicKey: string;
  },
): Promise<{ envelope: PrivateResponseEnvelopeV1; draft: PrivateResponseDraftV1 }> {
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
      nonce: bytesToBase64Url(randomBytes(DRAFT_NONCE_BYTES)),
    },
    input.allowedInviteeIds,
    trustedEvaluator,
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
    evaluatorKeyWrap: "",
  };
  const responseKeyBytes = randomBytes(RESPONSE_KEY_BYTES);
  let paddedPlaintext: Uint8Array | null = null;
  let sharedSecret: Uint8Array | null = null;
  try {
    const responseKey = await importAesKey(responseKeyBytes, ["encrypt"]);
    paddedPlaintext = serializePaddedDraft(draft);
    const payloadFrame = await aesGcmSeal(
      responseKey,
      paddedPlaintext,
      privateResponseAad("payload", envelopeBase),
    );

    const policyHash = strictBase64UrlBytes(
      draft.policyHash,
      POLICY_HASH_BYTES,
      "policyHash",
    );
    const userKek = await deriveHkdfAesKey(
      input.accountRootSecret,
      policyHash,
      privateResponseAad("user-key-derivation", envelopeBase),
      ["encrypt"],
    );
    const userWrapFrame = await aesGcmSeal(
      userKek,
      responseKeyBytes,
      privateResponseAad("user-key-wrap", envelopeBase),
    );

    const subtle = cryptoApi().subtle;
    const evaluatorPublicKey = await subtle.importKey(
      "raw",
      toArrayBuffer(trustedEvaluator.evaluatorPublicKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const ephemeralKeyPair = (await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const ephemeralPublicKey = new Uint8Array(
      await subtle.exportKey("raw", ephemeralKeyPair.publicKey),
    );
    if (
      ephemeralPublicKey.length !== EVALUATOR_PUBLIC_KEY_BYTES ||
      ephemeralPublicKey[0] !== 0x04
    ) {
      throw new PrivateResponseCryptoError(
        "The browser produced an invalid P-256 key.",
      );
    }
    sharedSecret = new Uint8Array(
      await subtle.deriveBits(
        { name: "ECDH", public: evaluatorPublicKey },
        ephemeralKeyPair.privateKey,
        256,
      ),
    );
    const evaluatorSalt = randomBytes(EVALUATOR_SALT_BYTES);
    const evaluatorKeyIdBytes = textEncoder.encode(
      trustedEvaluator.evaluatorKeyId,
    );
    const evaluatorKek = await deriveHkdfAesKey(
      sharedSecret,
      evaluatorSalt,
      concatenateBytes(
        privateResponseAad("evaluator-key-derivation", envelopeBase),
        evaluatorKeyIdBytes,
      ),
      ["encrypt"],
    );
    const evaluatorWrappedResponseKey = await aesGcmSeal(
      evaluatorKek,
      responseKeyBytes,
      concatenateBytes(
        privateResponseAad("evaluator-key-wrap", envelopeBase),
        evaluatorKeyIdBytes,
        ephemeralPublicKey,
        evaluatorSalt,
      ),
    );
    const evaluatorWrapFrame = concatenateBytes(
      ephemeralPublicKey,
      evaluatorSalt,
      evaluatorWrappedResponseKey,
    );

    if (
      payloadFrame.length !== PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES ||
      userWrapFrame.length !== PRIVATE_RESPONSE_USER_WRAP_BYTES ||
      evaluatorWrapFrame.length !== PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES
    ) {
      throw new PrivateResponseCryptoError(
        "The browser produced an invalid envelope size.",
      );
    }
    const derivedSigningKey = await deriveResponseSigningKey(
      input.accountRootSecret,
      envelopeBase,
    );
    const unsignedEnvelope = normalizePrivateResponseUnsignedEnvelope({
      ...envelopeBase,
      payloadCiphertext: bytesToBase64Url(payloadFrame),
      userKeyWrap: bytesToBase64Url(userWrapFrame),
      evaluatorKeyWrap: bytesToBase64Url(evaluatorWrapFrame),
      responseSigningPublicKey: bytesToBase64Url(derivedSigningKey.publicKey),
    });
    const ciphertextHash = await privateResponseEnvelopeHash(unsignedEnvelope);
    const signature = new Uint8Array(
      await cryptoApi().subtle.sign(
        { name: "Ed25519" },
        derivedSigningKey.privateKey,
        toArrayBuffer(
          privateResponseAuthorizationBytes(unsignedEnvelope, ciphertextHash),
        ),
      ),
    );
    const envelope = normalizePrivateResponseEnvelope({
      ...unsignedEnvelope,
      responseSignature: bytesToBase64Url(signature),
    });
    signature.fill(0);
    return { envelope, draft };
  } finally {
    responseKeyBytes.fill(0);
    paddedPlaintext?.fill(0);
    sharedSecret?.fill(0);
  }
}

export async function openPrivateResponse(
  input: OpenPrivateResponseInput,
): Promise<PrivateResponseDraftV1> {
  if (input.accountRootSecret.length !== RESPONSE_KEY_BYTES) {
    throw new PrivateResponseCryptoError("The account root secret has the wrong size.", {
      canSwitchDevice: true,
    });
  }
  const trustedEvaluator = await assertTrustedPolicy(input.policy);
  let responseKeyBytes: Uint8Array | null = null;
  let plaintext: Uint8Array | null = null;
  try {
    const normalizedEnvelope = normalizeEnvelopeCore(input.envelope);
    const envelope = normalizedEnvelope.envelope;
    if (
      envelope.eventId !== normalizeUuid(input.eventId, "eventId") ||
      envelope.inviteeId !== normalizeUuid(input.inviteeId, "inviteeId") ||
      envelope.policyHash !== input.policy.policyHash ||
      envelope.evaluatorKeyId !== trustedEvaluator.evaluatorKeyId
    ) {
      throw new PrivateResponseCryptoError(
        "The saved private response belongs to a different event policy.",
      );
    }
    const ciphertextHash = await privateResponseEnvelopeHash(envelope);
    if (
      normalizedEnvelope.storedCiphertextHash !== null &&
      normalizedEnvelope.storedCiphertextHash !== ciphertextHash
    ) {
      throw new PrivateResponseCryptoError(
        "The saved private response does not match its stored ciphertext hash.",
        { canSwitchDevice: true },
      );
    }
    await verifyResponseAuthorization(
      envelope,
      input.accountRootSecret,
      ciphertextHash,
    );
    const policyHash = strictBase64UrlBytes(
      envelope.policyHash,
      POLICY_HASH_BYTES,
      "policyHash",
    );
    const userKek = await deriveHkdfAesKey(
      input.accountRootSecret,
      policyHash,
      privateResponseAad("user-key-derivation", envelope),
      ["decrypt"],
    );
    responseKeyBytes = await aesGcmOpen(
      userKek,
      strictBase64UrlBytes(
        envelope.userKeyWrap,
        PRIVATE_RESPONSE_USER_WRAP_BYTES,
        "userKeyWrap",
      ),
      privateResponseAad("user-key-wrap", envelope),
    );
    const responseKey = await importAesKey(responseKeyBytes, ["decrypt"]);
    plaintext = await aesGcmOpen(
      responseKey,
      strictBase64UrlBytes(
        envelope.payloadCiphertext,
        PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES,
        "payloadCiphertext",
      ),
      privateResponseAad("payload", envelope),
    );
    const draft = parsePaddedDraft(
      plaintext,
      input.allowedInviteeIds,
      trustedEvaluator,
    );
    assertDraftMatchesEnvelope(draft, envelope);
    return draft;
  } catch (error) {
    if (error instanceof PrivateResponseCryptoError && error.canSwitchDevice) {
      throw error;
    }
    throw new PrivateResponseCryptoError(
      error instanceof Error
        ? error.message
        : "This device could not open the saved private response.",
      { canSwitchDevice: true },
    );
  } finally {
    responseKeyBytes?.fill(0);
    plaintext?.fill(0);
  }
}

export async function privateResponseEnvelopeHash(
  envelope: PrivateResponseEnvelopeV1 | Omit<PrivateResponseEnvelopeV1, "responseSignature">,
): Promise<string> {
  const digest = await cryptoApi().subtle.digest(
    "SHA-256",
    toArrayBuffer(textEncoder.encode(canonicalEnvelopeJson(envelope))),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

export function newConditionGroupId(): string {
  return randomUuid();
}
