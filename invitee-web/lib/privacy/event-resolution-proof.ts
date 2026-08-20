"use client";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  normalizeEvaluatorPublicKey,
  publicRuntimeValue,
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
      attendingMemberIds?: string[];
      attendanceRevealed: boolean;
      guestStates?: Array<{
        memberId: string;
        status: "going" | "cant_commit" | "no_response";
        missedDeadline: boolean;
      }>;
      resolvedAt: string;
      attestation?: EvaluationResultAttestationV1;
    }
  | {
      status: "not_confirmed";
      resolvedAt: string;
      attestation?: EvaluationResultAttestationV1;
    };

export type DisplayableEventResolution =
  | VerifiableEventResolution
  | { status: "verification_unavailable" };

export type EventResolutionVerificationContext = {
  eventId: string;
  rsvpDeadline: string | null;
  privateResponsePolicy: PrivateResponsePolicyV1 | null;
  inviteeIds?: string[];
  minimumParticipants?: number;
  requiredGroups?: Array<{ memberIDs: string[] }>;
};

function simpleBackendResolution(
  context: EventResolutionVerificationContext,
  value: unknown,
): VerifiableEventResolution {
  if (
    context.privateResponsePolicy !== null ||
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !context.rsvpDeadline ||
    !Array.isArray(context.inviteeIds) ||
    !Number.isInteger(context.minimumParticipants) ||
    !Array.isArray(context.requiredGroups)
  ) invalidProof();
  const raw = value as Record<string, unknown>;
  if (raw.attestation !== undefined) invalidProof();
  const resolvedAt = canonicalTimestamp(raw.resolvedAt);
  if (raw.status === "not_confirmed") {
    if (resolvedAt < canonicalTimestamp(context.rsvpDeadline)) invalidProof();
    return { status: "not_confirmed", resolvedAt };
  }
  if (raw.status !== "confirmed" || raw.attendanceRevealed !== true) invalidProof();
  if (
    !Array.isArray(raw.attendingMemberIds) ||
    raw.attendingMemberIds[0] !== "host" ||
    raw.attendingMemberIds.some((member) => typeof member !== "string") ||
    new Set(raw.attendingMemberIds).size !== raw.attendingMemberIds.length
  ) invalidProof();
  const attendingMemberIds = raw.attendingMemberIds as string[];
  const allowed = new Set(["host", ...context.inviteeIds]);
  if (
    attendingMemberIds.some((member) => !allowed.has(member)) ||
    attendingMemberIds.length < context.minimumParticipants! ||
    !context.requiredGroups!.every((group) =>
      group.memberIDs.some((member) => attendingMemberIds.includes(member)),
    )
  ) invalidProof();
  let guestStates: Array<{
    memberId: string;
    status: "going" | "cant_commit" | "no_response";
    missedDeadline: boolean;
  }> | undefined;
  if (raw.guestStates !== undefined) {
    if (!Array.isArray(raw.guestStates)) invalidProof();
    guestStates = raw.guestStates.map((unknownState) => {
      const state = exactRecord(unknownState, ["memberId", "status", "missedDeadline"]);
      if (
        typeof state.memberId !== "string" ||
        !context.inviteeIds!.includes(state.memberId) ||
        !["going", "cant_commit", "no_response"].includes(state.status as string) ||
        typeof state.missedDeadline !== "boolean"
      ) invalidProof();
      return state as {
        memberId: string;
        status: "going" | "cant_commit" | "no_response";
        missedDeadline: boolean;
      };
    });
  }
  return {
    status: "confirmed",
    attendingMemberIds,
    attendanceRevealed: true,
    ...(guestStates ? { guestStates } : {}),
    resolvedAt,
  };
}

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
    publicRuntimeValue("HERD_EVALUATOR_RESULT_SIGNING_KEY_ID"),
  );
  const configuredPublicKey =
    publicRuntimeValue("HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY");
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
      ? [
          "status",
          ...("attendanceRevealed" in (value as object) ? ["attendanceRevealed"] : []),
          ...(Array.isArray((value as { attendingMemberIds?: unknown }).attendingMemberIds)
            ? ["attendingMemberIds"]
            : []),
          ...("guestStates" in (value as object) ? ["guestStates"] : []),
          "resolvedAt",
          "attestation",
        ]
      : ["status", "resolvedAt", "attestation"],
  );
  if (resolution.status !== "confirmed" && resolution.status !== "not_confirmed") {
    invalidProof();
  }
  const status = resolution.status;
  const resolvedAt = canonicalTimestamp(resolution.resolvedAt);
  if (context.rsvpDeadline === null) invalidProof();
  const deadline = canonicalTimestamp(context.rsvpDeadline);

  let attendingMemberIds: string[] | undefined;
  let guestStates: Array<{
    memberId: string;
    status: "going" | "cant_commit" | "no_response";
    missedDeadline: boolean;
  }> | undefined;
  const attendanceRevealed = status === "confirmed"
    ? typeof resolution.attendanceRevealed === "boolean"
      ? resolution.attendanceRevealed
      : resolvedAt >= deadline
    : resolvedAt >= deadline;
  if (status === "confirmed") {
    if (
      resolution.attendanceRevealed !== undefined &&
      typeof resolution.attendanceRevealed !== "boolean"
    ) invalidProof();
    if (
      attendanceRevealed &&
      (!Array.isArray(resolution.attendingMemberIds) ||
      resolution.attendingMemberIds.length < 1 ||
      resolution.attendingMemberIds.some(
        (memberId) => typeof memberId !== "string" || memberId.length < 1,
      ) ||
      new Set(resolution.attendingMemberIds).size !==
        resolution.attendingMemberIds.length)
    ) {
      invalidProof();
    }
    if (attendanceRevealed) {
      attendingMemberIds = resolution.attendingMemberIds as string[];
      if (resolution.guestStates !== undefined && !Array.isArray(resolution.guestStates)) {
        invalidProof();
      }
      guestStates = Array.isArray(resolution.guestStates) ? resolution.guestStates.map((raw) => {
        const state = exactRecord(raw, ["memberId", "status", "missedDeadline"]);
        if (
          typeof state.memberId !== "string" ||
          !["going", "cant_commit", "no_response"].includes(state.status as string) ||
          typeof state.missedDeadline !== "boolean"
        ) {
          invalidProof();
        }
        return state as {
          memberId: string;
          status: "going" | "cant_commit" | "no_response";
          missedDeadline: boolean;
        };
      }) : undefined;
    }
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
  const rawSignedResult = signedDocument.result;
  const legacyRevealedResult = Boolean(
    attendanceRevealed &&
      rawSignedResult &&
      typeof rawSignedResult === "object" &&
      !Array.isArray(rawSignedResult) &&
      !("revealAttendance" in rawSignedResult),
  );
  const signedResult = exactRecord(
    rawSignedResult,
    status === "confirmed"
      ? [
          "protocolVersion",
          "eventId",
          "policyHash",
          "batchHash",
          "evaluatorKeyId",
          "status",
          ...(legacyRevealedResult ? [] : ["revealAttendance"]),
          ...(attendanceRevealed ? ["attendingMemberIds"] : []),
        ]
      : [
          "protocolVersion",
          "eventId",
          "policyHash",
          "batchHash",
          "evaluatorKeyId",
          "status",
          ...(legacyRevealedResult ? [] : ["revealAttendance"]),
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
    ...(legacyRevealedResult ? {} : { revealAttendance: attendanceRevealed }),
    ...(status === "confirmed" && attendanceRevealed
      ? { attendingMemberIds: attendingMemberIds! }
      : {}),
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
        ...(attendanceRevealed ? { attendingMemberIds: attendingMemberIds! } : {}),
        attendanceRevealed,
        ...(guestStates ? { guestStates } : {}),
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
    if (context.privateResponsePolicy === null) {
      return simpleBackendResolution(context, value);
    }
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
