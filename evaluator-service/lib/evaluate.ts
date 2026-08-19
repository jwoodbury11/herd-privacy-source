import {
  resolvePrivateEvent,
} from "@/vendor/privacy-evaluator/fixed-point.mjs";
import {
  openPrivateResponseEnvelope,
  privateResponseEnvelopeConstants,
} from "@/vendor/privacy-evaluator/private-response-envelope.mjs";
import { openValidPrivateResponses } from "./open-valid-private-responses.mjs";

const PROTOCOL_VERSION = 1 as const;
const CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM" as const;
const PADDED_PLAINTEXT_BYTES = 4_096;
const RESPONSE_AUTHORIZATION_DOMAIN = "HERD-RESPONSE-AUTHORIZATION-V1";
const MAXIMUM_INVITEES = 19;
const MAXIMUM_REQUEST_BYTES = 256 * 1024;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,120}$/;
const encoder = new TextEncoder();
const fatalDecoder = new TextDecoder("utf-8", { fatal: true });

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

const POLICY_KEYS = [
  "protocolVersion",
  "cipherSuite",
  "policyHash",
  "canonicalDocument",
  "evaluatorKeyId",
  "evaluatorPublicKey",
  "evaluatorMeasurement",
  "releaseId",
  "paddedPlaintextBytes",
  "frozenAt",
] as const;

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
] as const;

export type EvaluatorBindings = {
  HERD_DEPLOYMENT_PROFILE?: string;
  HERD_EVALUATOR_TOKEN?: string;
  HERD_EVALUATOR_KEY_ID?: string;
  HERD_EVALUATOR_PRIVATE_KEY_PEM?: string;
  HERD_EVALUATOR_PRIVATE_KEY_JWK?: string;
  HERD_EVALUATOR_MEASUREMENT?: string;
  HERD_RELEASE_ID?: string;
  HERD_EVALUATOR_RESULT_SIGNING_KEY_ID?: string;
  HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK?: string;
  HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN?: string;
};

export type EvaluatorConfig = {
  token: string;
  keyId: string;
  privateKey: CryptoKey;
  publicKey: string;
  measurement: string;
  releaseId: string;
};

type RequiredGroup = {
  id: string;
  memberIDs: string[];
};

type CanonicalPolicyDocument = {
  protocolVersion: typeof PROTOCOL_VERSION;
  cipherSuite: typeof CIPHER_SUITE;
  event: {
    id: string;
    title: string;
    eventDate: string;
    endDate: string | null;
    hostName: string;
    locationName: string;
    locationAddress: string;
    eventDescription: string;
  };
  members: {
    id: string;
  }[];
  hostRules: {
    minimumParticipants: number;
    requiredGroups: RequiredGroup[];
  };
  rsvpDeadline: string;
  revealPolicy: "not_confirmed_or_confirmed_attendance";
  limits: {
    maximumParticipants: number;
    maximumConditionGroups: number;
    maximumMembersPerGroup: number;
    paddedPlaintextBytes: typeof PADDED_PLAINTEXT_BYTES;
  };
  evaluator: {
    keyId: string;
    publicKey: string;
    measurement: string;
  };
  releaseId: string;
};

type FrozenPolicy = {
  protocolVersion: typeof PROTOCOL_VERSION;
  cipherSuite: typeof CIPHER_SUITE;
  policyHash: string;
  canonicalDocument: string;
  evaluatorKeyId: string;
  evaluatorPublicKey: string;
  evaluatorMeasurement: string;
  releaseId: string;
  paddedPlaintextBytes: typeof PADDED_PLAINTEXT_BYTES;
  frozenAt: string;
};

type Envelope = {
  protocolVersion: typeof PROTOCOL_VERSION;
  cipherSuite: typeof CIPHER_SUITE;
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

type EvaluationSlot = {
  inviteeId: string;
  envelopeHash: string | null;
  envelope: Envelope | null;
};

export type EvaluationAuthorityClaim = {
  protocolVersion: typeof PROTOCOL_VERSION;
  eventId: string;
  policyHash: string;
  releaseId: string;
  evaluatorKeyId: string;
  rsvpDeadline: string;
  memberIds: string[];
  batchHash: string;
  revealAttendance: boolean;
  slots: Array<{
    inviteeId: string;
    envelopeHash: string | null;
    revision: number | null;
    responseSigningPublicKey: string | null;
  }>;
};

export type EvaluationResult = {
  protocolVersion: typeof PROTOCOL_VERSION;
  eventId: string;
  policyHash: string;
  batchHash: string;
  evaluatorKeyId: string;
  status: "not_confirmed" | "confirmed";
  revealAttendance: boolean;
  attendingMemberIds?: string[];
};

export class EvaluatorHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

function invalidRequest(): never {
  throw new EvaluatorHttpError(400, "invalid_request");
}

function serviceUnavailable(): never {
  throw new EvaluatorHttpError(503, "service_unavailable");
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest();
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    invalidRequest();
  }
}

function boundedString(
  value: unknown,
  minimum: number,
  maximum: number,
): string {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    invalidRequest();
  }
  return value;
}

function identifier(value: unknown): string {
  const result = boundedString(value, 1, 120);
  if (!KEY_ID_PATTERN.test(result)) invalidRequest();
  return result;
}

function uuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) invalidRequest();
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalidRequest();
  }
  return value as number;
}

function canonicalIsoTimestamp(value: unknown): string {
  if (typeof value !== "string") invalidRequest();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRequest();
  }
  return value;
}

function decodeBase64Url(
  value: unknown,
  expectedBytes: number,
): Uint8Array {
  if (
    typeof value !== "string" ||
    !value ||
    !BASE64URL_PATTERN.test(value) ||
    value.length % 4 === 1
  ) {
    invalidRequest();
  }
  let binary: string;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    invalidRequest();
  }
  const bytes = Uint8Array.from(binary!, (character) => character.charCodeAt(0));
  if (bytes.length !== expectedBytes || encodeBase64Url(bytes) !== value) {
    invalidRequest();
  }
  return bytes;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return encodeBase64Url(new Uint8Array(digest));
}

function constantTimeEqual(left: string, right: string): boolean {
  const maximumLength = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximumLength; index += 1) {
    difference |=
      (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function requiredBinding(
  bindings: EvaluatorBindings,
  name: keyof EvaluatorBindings,
  minimum: number,
  maximum: number,
): string {
  const value = bindings[name];
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    serviceUnavailable();
  }
  return value;
}

function decodeConfiguredBase64Url(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    !value ||
    !BASE64URL_PATTERN.test(value) ||
    value.length % 4 === 1
  ) {
    serviceUnavailable();
  }
  let binary: string;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    serviceUnavailable();
  }
  const bytes = Uint8Array.from(binary!, (character) => character.charCodeAt(0));
  if (bytes.length !== 32 || encodeBase64Url(bytes) !== value) {
    serviceUnavailable();
  }
  return bytes;
}

function sameBytes(left: Uint8Array, right: readonly number[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function readDerLength(bytes: Uint8Array, state: { offset: number }): number {
  if (state.offset >= bytes.length) serviceUnavailable();
  const first = bytes[state.offset++];
  if ((first & 0x80) === 0) return first;
  const width = first & 0x7f;
  if (width < 1 || width > 2 || state.offset + width > bytes.length) {
    serviceUnavailable();
  }
  let length = 0;
  for (let index = 0; index < width; index += 1) {
    length = length * 256 + bytes[state.offset++];
  }
  if (length < 128 || (width === 2 && length < 256)) serviceUnavailable();
  return length;
}

function readDerElement(
  bytes: Uint8Array,
  state: { offset: number },
  expectedTag: number,
): Uint8Array {
  if (state.offset >= bytes.length || bytes[state.offset++] !== expectedTag) {
    serviceUnavailable();
  }
  const length = readDerLength(bytes, state);
  if (length < 0 || state.offset + length > bytes.length) serviceUnavailable();
  const result = bytes.subarray(state.offset, state.offset + length);
  state.offset += length;
  return result;
}

function privateComponentsFromSec1Pem(value: string): {
  x: string;
  y: string;
  d: string;
} {
  if (value.length < 100 || value.length > 4_000 || value.includes("\u0000")) {
    serviceUnavailable();
  }
  const normalized = value.replaceAll("\r\n", "\n").trim();
  const match = normalized.match(
    /^-----BEGIN EC PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END EC PRIVATE KEY-----$/u,
  );
  if (!match) serviceUnavailable();
  const encoded = match[1].replaceAll("\n", "");
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    serviceUnavailable();
  }
  if (btoa(binary!) !== encoded) serviceUnavailable();
  const der = Uint8Array.from(binary!, (character) => character.charCodeAt(0));
  const outerState = { offset: 0 };
  const sequence = readDerElement(der, outerState, 0x30);
  if (outerState.offset !== der.length) serviceUnavailable();
  const state = { offset: 0 };
  if (!sameBytes(readDerElement(sequence, state, 0x02), [0x01])) {
    serviceUnavailable();
  }
  const privateScalar = readDerElement(sequence, state, 0x04);
  if (privateScalar.length !== 32) serviceUnavailable();

  const parameters = readDerElement(sequence, state, 0xa0);
  const parameterState = { offset: 0 };
  const curveOid = readDerElement(parameters, parameterState, 0x06);
  if (
    parameterState.offset !== parameters.length ||
    !sameBytes(curveOid, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
  ) {
    serviceUnavailable();
  }

  const publicContainer = readDerElement(sequence, state, 0xa1);
  const publicState = { offset: 0 };
  const bitString = readDerElement(publicContainer, publicState, 0x03);
  if (
    publicState.offset !== publicContainer.length ||
    bitString.length !== 66 ||
    bitString[0] !== 0x00 ||
    bitString[1] !== 0x04 ||
    state.offset !== sequence.length
  ) {
    serviceUnavailable();
  }
  return {
    x: encodeBase64Url(bitString.subarray(2, 34)),
    y: encodeBase64Url(bitString.subarray(34, 66)),
    d: encodeBase64Url(privateScalar),
  };
}

function privateComponentsFromJwk(value: string): {
  x: string;
  y: string;
  d: string;
} {
  let input: Record<string, unknown>;
  try {
    input = record(JSON.parse(value));
  } catch {
    serviceUnavailable();
  }
  if (input!.kty !== "EC" || input!.crv !== "P-256") serviceUnavailable();
  return {
    x: encodeBase64Url(decodeConfiguredBase64Url(input!.x)),
    y: encodeBase64Url(decodeConfiguredBase64Url(input!.y)),
    d: encodeBase64Url(decodeConfiguredBase64Url(input!.d)),
  };
}

export async function loadConfig(
  bindings: EvaluatorBindings,
): Promise<EvaluatorConfig> {
  const token = requiredBinding(bindings, "HERD_EVALUATOR_TOKEN", 32, 512);
  const keyId = requiredBinding(bindings, "HERD_EVALUATOR_KEY_ID", 1, 120);
  if (!KEY_ID_PATTERN.test(keyId)) serviceUnavailable();
  const measurement = requiredBinding(
    bindings,
    "HERD_EVALUATOR_MEASUREMENT",
    1,
    500,
  );
  const releaseId = requiredBinding(bindings, "HERD_RELEASE_ID", 1, 200);
  const encodedJwk = bindings.HERD_EVALUATOR_PRIVATE_KEY_JWK?.trim() || null;
  const sec1Pem = bindings.HERD_EVALUATOR_PRIVATE_KEY_PEM?.trim() || null;
  if ((encodedJwk === null) === (sec1Pem === null)) serviceUnavailable();
  const { x, y, d } = sec1Pem
    ? privateComponentsFromSec1Pem(sec1Pem)
    : privateComponentsFromJwk(encodedJwk!);
  const publicBytes = new Uint8Array(65);
  publicBytes[0] = 0x04;
  publicBytes.set(decodeConfiguredBase64Url(x), 1);
  publicBytes.set(decodeConfiguredBase64Url(y), 33);
  let privateKey: CryptoKey;
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
        key_ops: ["deriveBits"],
      },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
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
    releaseId,
  };
}

function normalizeRequiredGroups(
  value: unknown,
  memberIds: readonly string[],
): RequiredGroup[] {
  if (!Array.isArray(value) || value.length > memberIds.length) invalidRequest();
  const allowed = new Set(memberIds);
  const seenGroups = new Set<string>();
  const seenMembers = new Set<string>();
  let previousGroupId = "";
  return value.map((rawGroup) => {
    const group = record(rawGroup);
    exactKeys(group, ["id", "memberIDs"]);
    const id = uuid(group.id);
    if (seenGroups.has(id) || (previousGroupId && id.localeCompare(previousGroupId) <= 0)) {
      invalidRequest();
    }
    previousGroupId = id;
    seenGroups.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      invalidRequest();
    }
    let previousMemberId = "";
    const memberIDs = group.memberIDs.map((rawMemberId) => {
      const memberId = uuid(rawMemberId);
      if (
        !allowed.has(memberId) ||
        seenMembers.has(memberId) ||
        (previousMemberId && memberId.localeCompare(previousMemberId) <= 0)
      ) {
        invalidRequest();
      }
      previousMemberId = memberId;
      seenMembers.add(memberId);
      return memberId;
    });
    return { id, memberIDs };
  });
}

function normalizeCanonicalDocument(value: unknown): CanonicalPolicyDocument {
  const input = record(value);
  exactKeys(input, [
    "protocolVersion",
    "cipherSuite",
    "event",
    "members",
    "hostRules",
    "rsvpDeadline",
    "revealPolicy",
    "limits",
    "evaluator",
    "releaseId",
  ]);
  if (input.protocolVersion !== PROTOCOL_VERSION || input.cipherSuite !== CIPHER_SUITE) {
    invalidRequest();
  }

  const rawEvent = record(input.event);
  exactKeys(rawEvent, [
    "id",
    "title",
    "eventDate",
    "endDate",
    "hostName",
    "locationName",
    "locationAddress",
    "eventDescription",
  ]);
  const eventDate = canonicalIsoTimestamp(rawEvent.eventDate);
  const endDate =
    rawEvent.endDate === null ? null : canonicalIsoTimestamp(rawEvent.endDate);
  if (endDate !== null && endDate <= eventDate) invalidRequest();
  const event = {
    id: uuid(rawEvent.id),
    title: boundedString(rawEvent.title, 1, 120),
    eventDate,
    endDate,
    hostName: boundedString(rawEvent.hostName, 1, 80),
    locationName: boundedString(rawEvent.locationName, 0, 160),
    locationAddress: boundedString(rawEvent.locationAddress, 0, 300),
    eventDescription: boundedString(rawEvent.eventDescription, 0, 2_000),
  };

  if (
    !Array.isArray(input.members) ||
    input.members.length === 0 ||
    input.members.length > MAXIMUM_INVITEES
  ) {
    invalidRequest();
  }
  const seenMembers = new Set<string>();
  let previousMemberId = "";
  const members = input.members.map((rawMember) => {
    const member = record(rawMember);
    exactKeys(member, ["id"]);
    const id = uuid(member.id);
    if (
      seenMembers.has(id) ||
      (previousMemberId && id.localeCompare(previousMemberId) <= 0)
    ) {
      invalidRequest();
    }
    previousMemberId = id;
    seenMembers.add(id);
    return { id };
  });
  const memberIds = members.map(({ id }) => id);

  const rawHostRules = record(input.hostRules);
  exactKeys(rawHostRules, ["minimumParticipants", "requiredGroups"]);
  const hostRules = {
    minimumParticipants: integer(
      rawHostRules.minimumParticipants,
      2,
      members.length + 1,
    ),
    requiredGroups: normalizeRequiredGroups(rawHostRules.requiredGroups, memberIds),
  };

  const rsvpDeadline = canonicalIsoTimestamp(input.rsvpDeadline);
  if (rsvpDeadline >= eventDate) invalidRequest();
  if (input.revealPolicy !== "not_confirmed_or_confirmed_attendance") {
    invalidRequest();
  }

  const rawLimits = record(input.limits);
  exactKeys(rawLimits, [
    "maximumParticipants",
    "maximumConditionGroups",
    "maximumMembersPerGroup",
    "paddedPlaintextBytes",
  ]);
  const limits = {
    maximumParticipants: integer(
      rawLimits.maximumParticipants,
      members.length + 1,
      members.length + 1,
    ),
    maximumConditionGroups: integer(
      rawLimits.maximumConditionGroups,
      members.length,
      members.length,
    ),
    maximumMembersPerGroup: integer(
      rawLimits.maximumMembersPerGroup,
      members.length,
      members.length,
    ),
    paddedPlaintextBytes: integer(
      rawLimits.paddedPlaintextBytes,
      PADDED_PLAINTEXT_BYTES,
      PADDED_PLAINTEXT_BYTES,
    ) as typeof PADDED_PLAINTEXT_BYTES,
  };

  const rawEvaluator = record(input.evaluator);
  exactKeys(rawEvaluator, ["keyId", "publicKey", "measurement"]);
  const publicKeyBytes = decodeBase64Url(rawEvaluator.publicKey, 65);
  if (publicKeyBytes[0] !== 0x04) invalidRequest();
  const evaluator = {
    keyId: identifier(rawEvaluator.keyId),
    publicKey: encodeBase64Url(publicKeyBytes),
    measurement: boundedString(rawEvaluator.measurement, 1, 500),
  };

  return {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    event,
    members,
    hostRules,
    rsvpDeadline,
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits,
    evaluator,
    releaseId: boundedString(input.releaseId, 1, 200),
  };
}

async function normalizePolicy(
  value: unknown,
  config: EvaluatorConfig,
  now: Date,
): Promise<{ policy: FrozenPolicy; document: CanonicalPolicyDocument }> {
  const input = record(value);
  exactKeys(input, POLICY_KEYS);
  if (
    input.protocolVersion !== PROTOCOL_VERSION ||
    input.cipherSuite !== CIPHER_SUITE ||
    input.paddedPlaintextBytes !== PADDED_PLAINTEXT_BYTES
  ) {
    invalidRequest();
  }
  const canonicalDocument = boundedString(input.canonicalDocument, 2, 64 * 1024);
  let parsedDocument: unknown;
  try {
    parsedDocument = JSON.parse(canonicalDocument);
  } catch {
    invalidRequest();
  }
  const document = normalizeCanonicalDocument(parsedDocument);
  if (JSON.stringify(document) !== canonicalDocument) invalidRequest();
  const policyHash = encodeBase64Url(decodeBase64Url(input.policyHash, 32));
  if (!constantTimeEqual(await sha256Base64Url(canonicalDocument), policyHash)) {
    invalidRequest();
  }
  const evaluatorPublicKeyBytes = decodeBase64Url(input.evaluatorPublicKey, 65);
  if (evaluatorPublicKeyBytes[0] !== 0x04) invalidRequest();
  const evaluatorPublicKey = encodeBase64Url(evaluatorPublicKeyBytes);
  const evaluatorKeyId = identifier(input.evaluatorKeyId);
  const evaluatorMeasurement = boundedString(input.evaluatorMeasurement, 1, 500);
  const releaseId = boundedString(input.releaseId, 1, 200);
  if (
    evaluatorKeyId !== document.evaluator.keyId ||
    evaluatorPublicKey !== document.evaluator.publicKey ||
    evaluatorMeasurement !== document.evaluator.measurement ||
    releaseId !== document.releaseId ||
    evaluatorKeyId !== config.keyId ||
    evaluatorPublicKey !== config.publicKey ||
    evaluatorMeasurement !== config.measurement ||
    releaseId !== config.releaseId
  ) {
    invalidRequest();
  }
  const frozenAt = canonicalIsoTimestamp(input.frozenAt);
  const nowIso = now.toISOString();
  if (frozenAt > document.rsvpDeadline || frozenAt > nowIso) invalidRequest();
  return {
    policy: {
      protocolVersion: PROTOCOL_VERSION,
      cipherSuite: CIPHER_SUITE,
      policyHash,
      canonicalDocument,
      evaluatorKeyId,
      evaluatorPublicKey,
      evaluatorMeasurement,
      releaseId,
      paddedPlaintextBytes: PADDED_PLAINTEXT_BYTES,
      frozenAt,
    },
    document,
  };
}

function normalizeEnvelope(value: unknown): Envelope {
  const input = record(value);
  exactKeys(input, ENVELOPE_KEYS);
  if (input.protocolVersion !== PROTOCOL_VERSION || input.cipherSuite !== CIPHER_SUITE) {
    invalidRequest();
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    envelopeId: uuid(input.envelopeId),
    eventId: uuid(input.eventId),
    inviteeId: uuid(input.inviteeId),
    policyHash: encodeBase64Url(decodeBase64Url(input.policyHash, 32)),
    revision: integer(input.revision, 1, 1_000_000),
    accountKeyEpochId: uuid(input.accountKeyEpochId),
    evaluatorKeyId: identifier(input.evaluatorKeyId),
    payloadCiphertext: encodeBase64Url(
      decodeBase64Url(
        input.payloadCiphertext,
        privateResponseEnvelopeConstants.payloadFrameBytes,
      ),
    ),
    userKeyWrap: encodeBase64Url(
      decodeBase64Url(
        input.userKeyWrap,
        privateResponseEnvelopeConstants.userWrapBytes,
      ),
    ),
    evaluatorKeyWrap: encodeBase64Url(
      decodeBase64Url(
        input.evaluatorKeyWrap,
        privateResponseEnvelopeConstants.evaluatorWrapBytes,
      ),
    ),
    responseSigningPublicKey: encodeBase64Url(
      decodeBase64Url(input.responseSigningPublicKey, 32),
    ),
    responseSignature: encodeBase64Url(
      decodeBase64Url(input.responseSignature, 64),
    ),
  };
}

function envelopeCommitmentDocument(envelope: Envelope): string {
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

function responseAuthorizationDocument(
  envelope: Envelope,
  ciphertextHash: string,
): string {
  return JSON.stringify({
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
}

async function verifyResponseAuthorization(
  envelope: Envelope,
  ciphertextHash: string,
): Promise<void> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer(decodeBase64Url(envelope.responseSigningPublicKey, 32)),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      ownedArrayBuffer(decodeBase64Url(envelope.responseSignature, 64)),
      ownedArrayBuffer(encoder.encode(
        `${RESPONSE_AUTHORIZATION_DOMAIN}\0${responseAuthorizationDocument(
          envelope,
          ciphertextHash,
        )}`,
      )),
    );
    if (!valid) invalidRequest();
  } catch (error) {
    if (error instanceof EvaluatorHttpError) throw error;
    invalidRequest();
  }
}

async function normalizeSlots(
  value: unknown,
  eventId: string,
  policy: FrozenPolicy,
  document: CanonicalPolicyDocument,
): Promise<EvaluationSlot[]> {
  if (!Array.isArray(value) || value.length !== document.members.length) {
    invalidRequest();
  }
  const seenEnvelopeIds = new Set<string>();
  const seenEnvelopeHashes = new Set<string>();
  return Promise.all(
    value.map(async (rawSlot, index) => {
      const input = record(rawSlot);
      exactKeys(input, ["inviteeId", "envelopeHash", "envelope"]);
      const inviteeId = uuid(input.inviteeId);
      if (inviteeId !== document.members[index].id) invalidRequest();
      if (input.envelope === null || input.envelopeHash === null) {
        if (input.envelope !== null || input.envelopeHash !== null) invalidRequest();
        return { inviteeId, envelopeHash: null, envelope: null };
      }
      const envelopeHash = encodeBase64Url(decodeBase64Url(input.envelopeHash, 32));
      const envelope = normalizeEnvelope(input.envelope);
      if (
        envelope.eventId !== eventId ||
        envelope.inviteeId !== inviteeId ||
        envelope.policyHash !== policy.policyHash ||
        envelope.evaluatorKeyId !== policy.evaluatorKeyId ||
        seenEnvelopeIds.has(envelope.envelopeId) ||
        seenEnvelopeHashes.has(envelopeHash)
      ) {
        invalidRequest();
      }
      seenEnvelopeIds.add(envelope.envelopeId);
      seenEnvelopeHashes.add(envelopeHash);
      const computedHash = await sha256Base64Url(
        envelopeCommitmentDocument(envelope),
      );
      if (!constantTimeEqual(computedHash, envelopeHash)) invalidRequest();
      await verifyResponseAuthorization(envelope, envelopeHash);
      return { inviteeId, envelopeHash, envelope };
    }),
  );
}

async function normalizeEvaluationRequest(
  value: unknown,
  config: EvaluatorConfig,
  now: Date,
): Promise<{
  eventId: string;
  policy: FrozenPolicy;
  document: CanonicalPolicyDocument;
  batchHash: string;
  revealAttendance: boolean;
  slots: EvaluationSlot[];
}> {
  if (!Number.isFinite(now.getTime())) serviceUnavailable();
  const input = record(value);
  exactKeys(input, [
    "protocolVersion",
    "eventId",
    "policy",
    "batchHash",
    "revealAttendance",
    "slots",
  ]);
  if (input.protocolVersion !== PROTOCOL_VERSION) invalidRequest();
  const eventId = uuid(input.eventId);
  const { policy, document } = await normalizePolicy(input.policy, config, now);
  if (document.event.id !== eventId) invalidRequest();
  if (typeof input.revealAttendance !== "boolean") invalidRequest();
  const revealAttendance = input.revealAttendance;
  const batchHash = encodeBase64Url(decodeBase64Url(input.batchHash, 32));
  const slots = await normalizeSlots(input.slots, eventId, policy, document);
  const batchCommitment = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    eventId,
    policyHash: policy.policyHash,
    revealAttendance,
    slots: slots.map(({ inviteeId, envelopeHash }) => ({ inviteeId, envelopeHash })),
  });
  if (!constantTimeEqual(await sha256Base64Url(batchCommitment), batchHash)) {
    invalidRequest();
  }
  return { eventId, policy, document, batchHash, revealAttendance, slots };
}

/**
 * Returns only the non-secret facts needed by the independently administered
 * response authority. Production callers must authorize this exact claim
 * before any envelope is decrypted.
 */
export async function evaluationAuthorityClaim(
  value: unknown,
  config: EvaluatorConfig,
  now: Date,
): Promise<EvaluationAuthorityClaim> {
  const { eventId, policy, document, batchHash, revealAttendance, slots } =
    await normalizeEvaluationRequest(value, config, now);
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
      responseSigningPublicKey: envelope?.responseSigningPublicKey ?? null,
    })),
  };
}

export async function evaluate(
  value: unknown,
  config: EvaluatorConfig,
  now: Date,
): Promise<EvaluationResult> {
  const { eventId, policy, document, batchHash, revealAttendance, slots } =
    await normalizeEvaluationRequest(value, config, now);

  const inviteeIds = document.members.map(({ id }) => id);
  const responses = await openValidPrivateResponses(
    slots.filter(
      (slot): slot is EvaluationSlot & { envelopeHash: string; envelope: Envelope } =>
        slot.envelope !== null,
    ),
    (slot) =>
      openPrivateResponseEnvelope({
        envelope: slot.envelope,
        evaluatorPrivateKey: config.privateKey,
        expectedEvaluatorKeyId: config.keyId,
        allowedInviteeIds: inviteeIds,
        hostMinimumParticipants: document.hostRules.minimumParticipants,
      }),
  );

  let resolution: ReturnType<typeof resolvePrivateEvent>;
  try {
    resolution = resolvePrivateEvent(
      {
        eventId,
        hostMemberId: "host",
        inviteeIds,
        minimumParticipants: document.hostRules.minimumParticipants,
        requiredGroups: document.hostRules.requiredGroups,
      },
      responses,
    );
  } catch {
    invalidRequest();
  }

  const base = {
    protocolVersion: PROTOCOL_VERSION,
    eventId,
    policyHash: policy.policyHash,
    batchHash,
    evaluatorKeyId: config.keyId,
  };
  if (resolution!.status === "not_confirmed") {
    return { ...base, status: "not_confirmed", revealAttendance };
  }
  const attendingMemberIds = resolution!.attendingMemberIds;
  if (
    !Array.isArray(attendingMemberIds) ||
    attendingMemberIds[0] !== "host" ||
    attendingMemberIds.some(
      (memberId, index) =>
        index > 0 &&
        (memberId !== inviteeIds.filter((id) => attendingMemberIds.includes(id))[index - 1]),
    ) ||
    new Set(attendingMemberIds).size !== attendingMemberIds.length ||
    attendingMemberIds.slice(1).some((memberId) => !inviteeIds.includes(memberId))
  ) {
    serviceUnavailable();
  }
  return revealAttendance
    ? { ...base, status: "confirmed", revealAttendance, attendingMemberIds }
    : { ...base, status: "confirmed", revealAttendance };
}

export function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export function errorResponse(error: EvaluatorHttpError): Response {
  return jsonResponse({ error: { code: error.code } }, error.status);
}

export async function handleEvaluationRequest(
  request: Request,
  bindings: EvaluatorBindings,
  now = new Date(),
): Promise<Response> {
  try {
    const configuredToken = requiredBinding(
      bindings,
      "HERD_EVALUATOR_TOKEN",
      32,
      512,
    );
    const authorization = request.headers.get("authorization") ?? "";
    const expectedAuthorization = `Bearer ${configuredToken}`;
    if (!constantTimeEqual(authorization, expectedAuthorization)) {
      throw new EvaluatorHttpError(401, "unauthorized");
    }
    const mediaType = (request.headers.get("content-type") ?? "")
      .split(";", 1)[0]
      .trim()
      .toLowerCase();
    if (mediaType !== "application/json") invalidRequest();
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null) {
      const parsed = Number(contentLength);
      if (!Number.isInteger(parsed) || parsed < 0 || parsed > MAXIMUM_REQUEST_BYTES) {
        throw new EvaluatorHttpError(413, "request_too_large");
      }
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.length === 0) invalidRequest();
    if (bytes.length > MAXIMUM_REQUEST_BYTES) {
      throw new EvaluatorHttpError(413, "request_too_large");
    }
    let input: unknown;
    try {
      input = JSON.parse(fatalDecoder.decode(bytes));
    } catch {
      invalidRequest();
    }
    const config = await loadConfig(bindings);
    return jsonResponse(await evaluate(input, config, now), 200);
  } catch (error) {
    if (error instanceof EvaluatorHttpError) return errorResponse(error);
    return errorResponse(new EvaluatorHttpError(503, "service_unavailable"));
  }
}
