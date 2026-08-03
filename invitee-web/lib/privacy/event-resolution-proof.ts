"use client";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  normalizeEvaluatorPublicKey,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  type PrivateResponsePolicyV1,
} from "./protocol";

const MAXIMUM_CANONICAL_DOCUMENT_BYTES = 32_768;

export type EvaluationResultAttestationV1 = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  signingKeyId: string;
  evaluatedAt: string;
  canonicalDocument: string;
  signature: string;
};

export type VerifiableEventResolution =
  | { status: "pending"; retrying?: boolean }
  | {
      status: "confirmed";
      attendingMemberIds: string[];
      resolvedAt: string;
      attestation: EvaluationResultAttestationV1;
    }
  | {
      status: "not_confirmed";
      resolvedAt: string;
      attestation: EvaluationResultAttestationV1;
    };

export type DisplayableEventResolution =
  | VerifiableEventResolution
  | { status: "verification_unavailable" };

export type EventResolutionVerificationContext = {
  eventId: string;
  rsvpDeadline: string | null;
  privateResponsePolicy: PrivateResponsePolicyV1 | null;
};

export type EvaluationResultSigningPin = {
  signingKeyId: string;
  signingPublicKey: string;
};

export class EventResolutionProofError extends Error {
  constructor() {
    super("The final event result could not be verified.");
    this.name = "EventResolutionProofError";
  }
}

function invalidProof(): never {
  throw new EventResolutionProofError();
}

function exactRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalidProof();
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    invalidProof();
  }
  return record;
}

function canonicalBase64Url(value: unknown, byteLength: number): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) invalidProof();
  try {
    const bytes = base64UrlToBytes(value);
    if (bytes.length !== byteLength || bytesToBase64Url(bytes) !== value) invalidProof();
    return value;
  } catch {
    invalidProof();
  }
}

function canonicalIdentifier(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(value)
  ) {
    invalidProof();
  }
  return value;
}

function canonicalUuid(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value,
    )
  ) {
    invalidProof();
  }
  return value;
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string") invalidProof();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidProof();
  }
  return value;
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

export function configuredEvaluationResultSigningPin(): EvaluationResultSigningPin {
  const signingKeyId = canonicalIdentifier(
    process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
  );
  const configuredPublicKey =
    process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY;
  if (typeof configuredPublicKey !== "string") invalidProof();
  let signingPublicKey: string;
  try {
    signingPublicKey = normalizeEvaluatorPublicKey(configuredPublicKey);
  } catch {
    invalidProof();
  }
  const bytes = base64UrlToBytes(signingPublicKey);
  if (
    bytes.length !== 65 ||
    bytes[0] !== 0x04 ||
    bytesToBase64Url(bytes) !== signingPublicKey
  ) {
    invalidProof();
  }
  return { signingKeyId, signingPublicKey };
}

export async function verifyEventResolutionProof(
  context: EventResolutionVerificationContext,
  value: unknown,
  pin: EvaluationResultSigningPin,
): Promise<VerifiableEventResolution> {
  const policy = context.privateResponsePolicy;
  if (!policy || policy.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION) {
    invalidProof();
  }
  const resolution = exactRecord(
    value,
    (value as { status?: unknown } | null)?.status === "confirmed"
      ? ["status", "attendingMemberIds", "resolvedAt", "attestation"]
      : ["status", "resolvedAt", "attestation"],
  );
  if (resolution.status !== "confirmed" && resolution.status !== "not_confirmed") {
    invalidProof();
  }
  const status = resolution.status;
  const resolvedAt = canonicalTimestamp(resolution.resolvedAt);
  if (
    context.rsvpDeadline === null ||
    resolvedAt < canonicalTimestamp(context.rsvpDeadline)
  ) {
    invalidProof();
  }

  let attendingMemberIds: string[] | undefined;
  if (status === "confirmed") {
    if (
      !Array.isArray(resolution.attendingMemberIds) ||
      resolution.attendingMemberIds.length < 1 ||
      resolution.attendingMemberIds.some(
        (memberId) => typeof memberId !== "string" || memberId.length < 1,
      ) ||
      new Set(resolution.attendingMemberIds).size !==
        resolution.attendingMemberIds.length
    ) {
      invalidProof();
    }
    attendingMemberIds = resolution.attendingMemberIds as string[];
  }

  const attestation = exactRecord(
    resolution.attestation,
    [
      "protocolVersion",
      "signingKeyId",
      "evaluatedAt",
      "canonicalDocument",
      "signature",
    ],
  );
  if (attestation.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION) invalidProof();
  const signingKeyId = canonicalIdentifier(attestation.signingKeyId);
  if (signingKeyId !== pin.signingKeyId) invalidProof();
  const evaluatedAt = canonicalTimestamp(attestation.evaluatedAt);
  if (evaluatedAt !== resolvedAt) invalidProof();
  if (
    typeof attestation.canonicalDocument !== "string" ||
    attestation.canonicalDocument.length < 2 ||
    new TextEncoder().encode(attestation.canonicalDocument).length >
      MAXIMUM_CANONICAL_DOCUMENT_BYTES
  ) {
    invalidProof();
  }
  const signature = canonicalBase64Url(attestation.signature, 64);

  let signedDocument: Record<string, unknown>;
  try {
    signedDocument = exactRecord(
      JSON.parse(attestation.canonicalDocument),
      [
        "protocolVersion",
        "signingKeyId",
        "relayRequestHash",
        "relayRequestId",
        "leaseId",
        "evaluatedAt",
        "result",
      ],
    );
  } catch {
    invalidProof();
  }
  const relayRequestHash = canonicalBase64Url(signedDocument.relayRequestHash, 32);
  const relayRequestId = canonicalUuid(signedDocument.relayRequestId);
  const leaseId = canonicalUuid(signedDocument.leaseId);
  const signedResult = exactRecord(
    signedDocument.result,
    status === "confirmed"
      ? [
          "protocolVersion",
          "eventId",
          "policyHash",
          "batchHash",
          "evaluatorKeyId",
          "status",
          "attendingMemberIds",
        ]
      : [
          "protocolVersion",
          "eventId",
          "policyHash",
          "batchHash",
          "evaluatorKeyId",
          "status",
      ],
  );
  const batchHash = canonicalBase64Url(signedResult.batchHash, 32);
  const expectedResult = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: context.eventId,
    policyHash: policy.policyHash,
    batchHash,
    evaluatorKeyId: policy.evaluatorKeyId,
    status,
    ...(status === "confirmed" ? { attendingMemberIds: attendingMemberIds! } : {}),
  };
  const expectedCanonicalDocument = JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    signingKeyId: pin.signingKeyId,
    relayRequestHash,
    relayRequestId,
    leaseId,
    evaluatedAt,
    result: expectedResult,
  });
  if (
    signedDocument.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    signedDocument.signingKeyId !== pin.signingKeyId ||
    signedDocument.evaluatedAt !== evaluatedAt ||
    JSON.stringify(signedResult) !== JSON.stringify(expectedResult) ||
    attestation.canonicalDocument !== expectedCanonicalDocument
  ) {
    invalidProof();
  }

  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer(base64UrlToBytes(pin.signingPublicKey)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    invalidProof();
  }
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      ownedArrayBuffer(base64UrlToBytes(signature)),
      ownedArrayBuffer(new TextEncoder().encode(attestation.canonicalDocument)),
    );
  } catch {
    invalidProof();
  }
  if (!verified) invalidProof();

  const normalizedAttestation: EvaluationResultAttestationV1 = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    signingKeyId,
    evaluatedAt,
    canonicalDocument: attestation.canonicalDocument,
    signature,
  };
  return status === "confirmed"
    ? {
        status,
        attendingMemberIds: attendingMemberIds!,
        resolvedAt,
        attestation: normalizedAttestation,
      }
    : {
        status,
        resolvedAt,
        attestation: normalizedAttestation,
      };
}

export async function displayableEventResolution(
  context: EventResolutionVerificationContext,
  value: unknown,
  pin?: EvaluationResultSigningPin,
): Promise<DisplayableEventResolution | null> {
  if (value === null || value === undefined) return null;
  if (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (value as { status?: unknown }).status === "pending"
  ) {
    const pending = value as { status: "pending"; retrying?: unknown };
    return pending.retrying === true
      ? { status: "pending", retrying: true }
      : { status: "pending" };
  }
  try {
    return await verifyEventResolutionProof(
      context,
      value,
      pin ?? configuredEvaluationResultSigningPin(),
    );
  } catch {
    // Missing proof, tampering, and historical signing-key rotation all have
    // the same safe outcome: never display an unsigned final answer.
    return { status: "verification_unavailable" };
  }
}
