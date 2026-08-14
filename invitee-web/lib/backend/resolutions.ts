import type { HerdBindings } from "@/db";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatenateBytes,
  PRIVATE_RESPONSE_CIPHER_SUITE,
  PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  type PrivateResponseEnvelopeV1,
  type PrivateResponsePolicyV1,
} from "@/lib/privacy/protocol";

import {
  getEvaluatorRelayConfig,
  getEvaluatorServiceConfig,
  getEvaluatorTransport,
} from "./config";
import { verifyStoredEventPolicyCertification } from "./evaluator-trust";
import { ApiError } from "./http";
import {
  parseResponseEnvelope,
  RESPONSE_ENVELOPE_SELECT,
  responseEnvelopeHash,
  unstoredResponseEnvelope,
  type ResponseEnvelopeRow,
} from "./response-envelopes";
import { recoverPendingResponseTransparency } from "./response-transparency";
import { sendResolutionTransitionNotifications } from "./resolution-notifications";
import type { EvaluationResultAttestation, EventResolution } from "./types";

type EventResolutionRow = {
  eventId: string;
  policyHash: string;
  status: string;
  batchHash: string | null;
  attendingMemberIds: string | null;
  resolvedAt: string | null;
  evaluationLeaseId: string | null;
  evaluationLeaseExpiresAt: string | null;
  evaluationRequestHash: string | null;
  resultAttestationProtocolVersion: number | null;
  resultAttestationSigningKeyId: string | null;
  resultAttestationEvaluatedAt: string | null;
  resultAttestationCanonicalDocument: string | null;
  resultAttestationSignature: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ResolutionReadableEvent = {
  id: string;
  title?: string;
  invitationsSent: boolean;
  rsvpDeadline: string | null;
  privateResponsePolicy: PrivateResponsePolicyV1 | null;
};

type EvaluatorSlot = {
  inviteeId: string;
  envelopeHash: string | null;
  envelope: PrivateResponseEnvelopeV1 | null;
};

type CanonicalPolicyFacts = {
  inviteeIds: string[];
  minimumParticipants: number;
  requiredGroups: { id: string; memberIDs: string[] }[];
};

const EVENT_RESOLUTION_SELECT = `SELECT
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

const EVALUATION_LEASE_MILLISECONDS = 30_000;
const RELAY_EVALUATION_LEASE_MILLISECONDS = 90_000;
const RELAY_PADDED_PLAINTEXT_BYTES = 327_680;
const RELAY_MAXIMUM_INNER_REQUEST_BYTES = 256 * 1_024;
const RELAY_CIPHERTEXT_BYTES = RELAY_PADDED_PLAINTEXT_BYTES + 12 + 16;
const RELAY_KEY_INFO_LABEL = "HERD-EVALUATOR-RELAY-KEY-V1\0";
const RELAY_AAD_LABEL = "HERD-EVALUATOR-RELAY-AAD-V1\0";
const RELAY_CAPABILITY_LABEL = "HERD-EVALUATOR-RELAY-CAPABILITY-V1\0";

export type EvaluatorRelayRequest = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  cipherSuite: typeof PRIVATE_RESPONSE_CIPHER_SUITE;
  evaluatorKeyId: string;
  ephemeralPublicKey: string;
  salt: string;
  ciphertext: string;
  capabilityMac: string;
};

export type EvaluationRelayJob = {
  eventId: string;
  evaluatorUrl: string;
  evaluatorHost: string;
  releaseId: string;
  leaseId: string;
  expiresAt: string;
  relayRequest: EvaluatorRelayRequest;
};

export type EvaluationStartResult =
  | { kind: "relay"; job: EvaluationRelayJob }
  | { kind: "pending" }
  | { kind: "resolved"; resolution: EventResolution };

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

function isCanonicalBase64UrlBytes(value: unknown, bytes: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  try {
    const decoded = base64UrlToBytes(value);
    return decoded.length === bytes && bytesToBase64Url(decoded) === value;
  } catch {
    return false;
  }
}

function evaluationFailureCode(error: unknown): string {
  if (
    error instanceof ApiError &&
    /^[a-z0-9_]{1,80}$/u.test(error.code)
  ) {
    return error.code;
  }
  return "unexpected_evaluation_error";
}

function reportEvaluationFailure(eventId: string, error: unknown): void {
  console.error("Herd event evaluation failed", {
    eventId,
    code: evaluationFailureCode(error),
  });
}

function storedResultAttestation(
  row: EventResolutionRow,
): EvaluationResultAttestation | undefined {
  const values = [
    row.resultAttestationProtocolVersion,
    row.resultAttestationSigningKeyId,
    row.resultAttestationEvaluatedAt,
    row.resultAttestationCanonicalDocument,
    row.resultAttestationSignature,
  ];
  if (values.every((value) => value === null)) return undefined;
  if (
    row.resultAttestationProtocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    typeof row.resultAttestationSigningKeyId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(
      row.resultAttestationSigningKeyId,
    ) ||
    typeof row.resultAttestationEvaluatedAt !== "string" ||
    !Number.isFinite(Date.parse(row.resultAttestationEvaluatedAt)) ||
    new Date(Date.parse(row.resultAttestationEvaluatedAt)).toISOString() !==
      row.resultAttestationEvaluatedAt ||
    row.resultAttestationEvaluatedAt !== row.resolvedAt ||
    typeof row.resultAttestationCanonicalDocument !== "string" ||
    row.resultAttestationCanonicalDocument.length < 2 ||
    row.resultAttestationCanonicalDocument.length > 32_768 ||
    !isCanonicalBase64UrlBytes(row.resultAttestationSignature, 64)
  ) {
    // Historical or partially migrated rows deliberately remain readable, but
    // omit proof so current clients render a fail-closed unavailable state.
    return undefined;
  }
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    signingKeyId: row.resultAttestationSigningKeyId,
    evaluatedAt: row.resultAttestationEvaluatedAt,
    canonicalDocument: row.resultAttestationCanonicalDocument,
    signature: row.resultAttestationSignature,
  };
}

function parseStoredResolution(
  row: EventResolutionRow | null,
  eventId: string,
  policyHash: string,
): EventResolution | null {
  if (!row) return null;
  if (row.eventId !== eventId || row.policyHash !== policyHash) {
    throw new ApiError(
      500,
      "event_resolution_corrupt",
      "The stored event result does not match its frozen policy.",
    );
  }
  if (row.status === "pending") {
    if (
      row.batchHash ||
      row.attendingMemberIds ||
      row.resolvedAt ||
      row.evaluationLeaseId ||
      row.evaluationLeaseExpiresAt ||
      row.evaluationRequestHash ||
      row.resultAttestationProtocolVersion !== null ||
      row.resultAttestationSigningKeyId !== null ||
      row.resultAttestationEvaluatedAt !== null ||
      row.resultAttestationCanonicalDocument !== null ||
      row.resultAttestationSignature !== null
    ) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid.",
      );
    }
    return { status: "pending" };
  }
  if (row.status === "evaluating") {
    if (
      row.attendingMemberIds ||
      row.resolvedAt ||
      row.resultAttestationProtocolVersion !== null ||
      row.resultAttestationSigningKeyId !== null ||
      row.resultAttestationEvaluatedAt !== null ||
      row.resultAttestationCanonicalDocument !== null ||
      row.resultAttestationSignature !== null ||
      !row.evaluationLeaseId ||
      row.evaluationLeaseId.length > 80 ||
      !row.evaluationLeaseExpiresAt ||
      !Number.isFinite(Date.parse(row.evaluationLeaseExpiresAt)) ||
      !(
        (!row.batchHash && !row.evaluationRequestHash) ||
        (isCanonicalBase64UrlBytes(row.batchHash, 32) &&
          isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32))
      )
    ) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid.",
      );
    }
    return { status: "pending" };
  }
  if (row.status === "not_confirmed") {
    if (
      !isCanonicalBase64UrlBytes(row.batchHash, 32) ||
      row.attendingMemberIds ||
      !row.resolvedAt ||
      !Number.isFinite(Date.parse(row.resolvedAt)) ||
      row.evaluationLeaseId ||
      row.evaluationLeaseExpiresAt ||
      (row.evaluationRequestHash !== null &&
        !isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32))
    ) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid.",
      );
    }
    const attestation = storedResultAttestation(row);
    return {
      status: "not_confirmed",
      resolvedAt: row.resolvedAt,
      ...(attestation ? { attestation } : {}),
    };
  }
  if (row.status === "confirmed") {
    if (
      !isCanonicalBase64UrlBytes(row.batchHash, 32) ||
      !row.resolvedAt ||
      !Number.isFinite(Date.parse(row.resolvedAt)) ||
      row.evaluationLeaseId ||
      row.evaluationLeaseExpiresAt ||
      (row.evaluationRequestHash !== null &&
        !isCanonicalBase64UrlBytes(row.evaluationRequestHash, 32))
    ) {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid.",
      );
    }
    if (row.attendingMemberIds === null) {
      const attestation = storedResultAttestation(row);
      return {
        status: "confirmed",
        attendanceRevealed: false,
        resolvedAt: row.resolvedAt,
        ...(attestation ? { attestation } : {}),
      };
    }
    try {
      const attendingMemberIds: unknown = JSON.parse(row.attendingMemberIds);
      if (
        !Array.isArray(attendingMemberIds) ||
        attendingMemberIds.length === 0 ||
        attendingMemberIds.some((memberId) => typeof memberId !== "string") ||
        new Set(attendingMemberIds).size !== attendingMemberIds.length
      ) {
        throw new TypeError();
      }
      const attestation = storedResultAttestation(row);
      return {
        status: "confirmed",
        attendingMemberIds,
        attendanceRevealed: true,
        resolvedAt: row.resolvedAt,
        ...(attestation ? { attestation } : {}),
      };
    } catch {
      throw new ApiError(
        500,
        "event_resolution_corrupt",
        "The stored event result is invalid.",
      );
    }
  }
  throw new ApiError(
    500,
    "event_resolution_corrupt",
    "The stored event result has an unsupported status.",
  );
}

function requiresDeadlineReveal(
  row: EventResolutionRow,
  event: ResolutionReadableEvent,
  nowIso: string,
): boolean {
  return Boolean(
    event.rsvpDeadline &&
      nowIso >= event.rsvpDeadline &&
      (row.status === "confirmed" || row.status === "not_confirmed") &&
      row.resolvedAt &&
      row.resolvedAt < event.rsvpDeadline,
  );
}

async function withRevealedGuestStates(
  db: D1Database,
  event: ResolutionReadableEvent,
  resolution: EventResolution | null,
): Promise<EventResolution | null> {
  if (
    resolution?.status !== "confirmed" ||
    !resolution.attendanceRevealed ||
    !resolution.attendingMemberIds ||
    !event.rsvpDeadline
  ) {
    return resolution;
  }
  const rows = await db
    .prepare(
      `SELECT invitees.id AS memberId,
              MIN(response_envelopes.created_at) AS firstResponseAt
       FROM invitees
       LEFT JOIN response_envelopes
         ON response_envelopes.invitee_id = invitees.id
       WHERE invitees.event_id = ?
       GROUP BY invitees.id
       ORDER BY invitees.id ASC`,
    )
    .bind(event.id)
    .all<{ memberId: string; firstResponseAt: string | null }>();
  const attending = new Set(resolution.attendingMemberIds);
  return {
    ...resolution,
    guestStates: rows.results.map(({ memberId, firstResponseAt }) => ({
      memberId,
      status: attending.has(memberId)
        ? ("going" as const)
        : firstResponseAt
          ? ("cant_commit" as const)
          : ("no_response" as const),
      missedDeadline: !firstResponseAt || firstResponseAt > event.rsvpDeadline!,
    })),
  };
}

async function resetResolvedForReevaluation(
  db: D1Database,
  eventId: string,
  policyHash: string,
  nowIso: string,
): Promise<void> {
  await db
    .prepare(
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
       WHERE event_id = ? AND policy_hash = ?`,
    )
    .bind(nowIso, eventId, policyHash)
    .run();
}

async function loadResolutionRow(
  db: D1Database,
  eventId: string,
): Promise<EventResolutionRow | null> {
  return db
    .prepare(`${EVENT_RESOLUTION_SELECT} WHERE event_id = ?`)
    .bind(eventId)
    .first<EventResolutionRow>();
}

export function prepareInsertPendingEventResolution(
  db: D1Database,
  eventId: string,
  policyHash: string,
  nowIso: string,
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT OR IGNORE INTO event_resolutions
        (event_id, policy_hash, status, batch_hash, attending_member_ids,
         resolved_at, evaluation_lease_id, evaluation_lease_expires_at,
         evaluation_request_hash, result_attestation_protocol_version,
         result_attestation_signing_key_id, result_attestation_evaluated_at,
         result_attestation_canonical_document, result_attestation_signature,
         created_at, updated_at)
       VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, NULL, NULL,
               NULL, NULL, NULL, NULL, NULL, ?, ?)`,
    )
    .bind(eventId, policyHash, nowIso, nowIso);
}

async function ensurePendingResolution(
  db: D1Database,
  eventId: string,
  policyHash: string,
  nowIso: string,
): Promise<EventResolutionRow> {
  await prepareInsertPendingEventResolution(db, eventId, policyHash, nowIso).run();
  const row = await loadResolutionRow(db, eventId);
  if (!row) {
    throw new ApiError(
      500,
      "event_resolution_unavailable",
      "The event result could not be initialized.",
    );
  }
  parseStoredResolution(row, eventId, policyHash);
  return row;
}

async function canonicalPolicyFacts(
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  policy: PrivateResponsePolicyV1,
): Promise<CanonicalPolicyFacts> {
  if (
    policy.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    policy.cipherSuite !== PRIVATE_RESPONSE_CIPHER_SUITE ||
    policy.paddedPlaintextBytes !== PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES ||
    (await sha256Base64Url(policy.canonicalDocument)) !== policy.policyHash ||
    !(await verifyStoredEventPolicyCertification(bindings, policy))
  ) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be validated.",
    );
  }

  let document: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(policy.canonicalDocument);
    if (!isRecord(parsed)) throw new TypeError();
    document = parsed;
  } catch {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be validated.",
    );
  }
  const eventDocument = document.event;
  const evaluator = document.evaluator;
  const hostRules = document.hostRules;
  if (
    document.protocolVersion !== policy.protocolVersion ||
    document.cipherSuite !== policy.cipherSuite ||
    document.rsvpDeadline !== event.rsvpDeadline ||
    document.releaseId !== policy.releaseId ||
    !isRecord(eventDocument) ||
    eventDocument.id !== event.id ||
    !isRecord(evaluator) ||
    evaluator.keyId !== policy.evaluatorKeyId ||
    evaluator.publicKey !== policy.evaluatorPublicKey ||
    evaluator.measurement !== policy.evaluatorMeasurement ||
    !isRecord(hostRules) ||
    !Number.isInteger(hostRules.minimumParticipants) ||
    !Array.isArray(hostRules.requiredGroups) ||
    !Array.isArray(document.members)
  ) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be validated.",
    );
  }

  const inviteeIds: string[] = [];
  for (const member of document.members) {
    if (!isRecord(member) || typeof member.id !== "string" || !member.id) {
      throw new ApiError(
        500,
        "event_policy_corrupt",
        "The frozen event policy contains an invalid member.",
      );
    }
    inviteeIds.push(member.id);
  }
  if (
    new Set(inviteeIds).size !== inviteeIds.length ||
    inviteeIds.some((id, index) => index > 0 && inviteeIds[index - 1].localeCompare(id) >= 0)
  ) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy contains invalid membership.",
    );
  }

  const requiredGroups: { id: string; memberIDs: string[] }[] = [];
  for (const group of hostRules.requiredGroups) {
    if (
      !isRecord(group) ||
      typeof group.id !== "string" ||
      !Array.isArray(group.memberIDs) ||
      group.memberIDs.some((id) => typeof id !== "string" || !inviteeIds.includes(id))
    ) {
      throw new ApiError(
        500,
        "event_policy_corrupt",
        "The frozen event policy contains invalid attendance rules.",
      );
    }
    requiredGroups.push({
      id: group.id,
      memberIDs: group.memberIDs as string[],
    });
  }
  return {
    inviteeIds,
    minimumParticipants: hostRules.minimumParticipants as number,
    requiredGroups,
  };
}

async function buildEvaluatorBatch(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  policy: PrivateResponsePolicyV1,
  facts: CanonicalPolicyFacts,
  nowIso: string,
): Promise<{ batchHash: string; revealAttendance: boolean; slots: EvaluatorSlot[] }> {
  const databaseMembers = await db
    .prepare("SELECT id FROM invitees WHERE event_id = ? ORDER BY id ASC")
    .bind(event.id)
    .all<{ id: string }>();
  if (
    databaseMembers.results.length !== facts.inviteeIds.length ||
    databaseMembers.results.some((member, index) => member.id !== facts.inviteeIds[index])
  ) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "Event membership no longer matches the frozen policy.",
    );
  }

  await recoverPendingResponseTransparency(db, bindings);

  const rows = await db
    .prepare(
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
       ORDER BY invitee_id ASC, revision DESC, created_at DESC`,
    )
    .bind(event.id)
    .all<ResponseEnvelopeRow>();
  const inviteeSet = new Set(facts.inviteeIds);
  const latest = new Map<string, PrivateResponseEnvelopeV1 & { ciphertextHash: string }>();
  for (const row of rows.results) {
    if (!inviteeSet.has(row.inviteeId) || latest.has(row.inviteeId)) continue;
    const stored = parseResponseEnvelope(row);
    if (
      !stored ||
      stored.eventId !== event.id ||
      stored.inviteeId !== row.inviteeId ||
      stored.policyHash !== policy.policyHash ||
      stored.evaluatorKeyId !== policy.evaluatorKeyId
    ) {
      continue;
    }
    const envelope = unstoredResponseEnvelope(stored);
    const ciphertextHash = await responseEnvelopeHash(envelope);
    if (ciphertextHash !== stored.ciphertextHash) continue;
    latest.set(row.inviteeId, { ...envelope, ciphertextHash });
  }

  const slots: EvaluatorSlot[] = facts.inviteeIds.map((inviteeId) => {
    const response = latest.get(inviteeId);
    if (!response) return { inviteeId, envelopeHash: null, envelope: null };
    const { ciphertextHash, ...envelope } = response;
    return { inviteeId, envelopeHash: ciphertextHash, envelope };
  });
  const revealAttendance = nowIso >= event.rsvpDeadline!;
  const batchDocument = JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: event.id,
    policyHash: policy.policyHash,
    revealAttendance,
    slots: slots.map(({ inviteeId, envelopeHash }) => ({
      inviteeId,
      envelopeHash,
    })),
  });
  return {
    batchHash: await sha256Base64Url(batchDocument),
    revealAttendance,
    slots,
  };
}

function evaluatorPolicyDescriptor(policy: PrivateResponsePolicyV1) {
  const {
    policySigningKeyId: _policySigningKeyId,
    policySignature: _policySignature,
    ...descriptor
  } = policy;
  void _policySigningKeyId;
  void _policySignature;
  return descriptor;
}

function validateEvaluatorResult(
  value: unknown,
  event: ResolutionReadableEvent,
  policy: PrivateResponsePolicyV1,
  facts: CanonicalPolicyFacts,
  batchHash: string,
  revealAttendance: boolean,
):
  | { status: "confirmed"; revealAttendance: false; legacyFormat: false }
  | { status: "confirmed"; revealAttendance: true; attendingMemberIds: string[]; legacyFormat: boolean }
  | { status: "not_confirmed"; revealAttendance: boolean; legacyFormat: boolean } {
  if (!isRecord(value) || (value.status !== "confirmed" && value.status !== "not_confirmed")) {
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
    ...(legacyFormat ? [] : ["revealAttendance"]),
    ...(value.status === "confirmed" && revealAttendance ? ["attendingMemberIds"] : []),
  ];
  if (
    !hasExactKeys(value, expectedKeys) ||
    value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    value.eventId !== event.id ||
    value.policyHash !== policy.policyHash ||
    value.batchHash !== batchHash ||
    value.evaluatorKeyId !== policy.evaluatorKeyId ||
    (!legacyFormat && value.revealAttendance !== revealAttendance)
  ) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned an invalid result.");
  }
  if (value.status === "not_confirmed") {
    return { status: "not_confirmed", revealAttendance, legacyFormat };
  }
  if (!revealAttendance) {
    return { status: "confirmed", revealAttendance: false, legacyFormat: false };
  }
  if (
    !Array.isArray(value.attendingMemberIds) ||
    value.attendingMemberIds.some((id) => typeof id !== "string") ||
    new Set(value.attendingMemberIds).size !== value.attendingMemberIds.length
  ) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned invalid attendance.");
  }
  const attendingMemberIds = value.attendingMemberIds as string[];
  const attending = new Set(attendingMemberIds);
  const ordered = ["host", ...facts.inviteeIds.filter((id) => attending.has(id))];
  if (
    !attending.has("host") ||
    ordered.length !== attending.size ||
    ordered.some((id, index) => attendingMemberIds[index] !== id) ||
    ordered.length < facts.minimumParticipants ||
    facts.requiredGroups.some(
      (group) => !group.memberIDs.some((memberId) => attending.has(memberId)),
    )
  ) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned invalid attendance.");
  }
  return {
    status: "confirmed",
    revealAttendance: true,
    attendingMemberIds: ordered,
    legacyFormat,
  };
}

async function callEvaluator(
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  policy: PrivateResponsePolicyV1,
  facts: CanonicalPolicyFacts,
  batchHash: string,
  revealAttendance: boolean,
  slots: EvaluatorSlot[],
) {
  const service = getEvaluatorServiceConfig(bindings);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  let response: Response;
  try {
    response = await fetch(service.url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${service.token}`,
        "content-type": "application/json",
        accept: "application/json",
        ...(service.sitesBypassToken
          ? {
              "OAI-Sites-Authorization": `Bearer ${service.sitesBypassToken}`,
            }
          : {}),
      },
      body: JSON.stringify({
        protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
        eventId: event.id,
        policy: evaluatorPolicyDescriptor(policy),
        batchHash,
        revealAttendance,
        slots,
      }),
      redirect: "manual",
      signal: controller.signal,
    });
  } catch (error) {
    const code =
      error instanceof Error && error.name === "AbortError"
        ? "evaluator_request_timeout"
        : "evaluator_network_error";
    throw new ApiError(
      503,
      code,
      "The private event result is temporarily unavailable.",
    );
  } finally {
    clearTimeout(timeout);
  }
  if (!response.ok) {
    throw new ApiError(
      503,
      `evaluator_http_${response.status}`,
      "The private event result is temporarily unavailable.",
    );
  }
  const text = await response.text();
  if (text.length > 32_768) {
    throw new ApiError(502, "invalid_evaluator_response", "The evaluator returned an invalid result.");
  }
  let value: unknown;
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
    revealAttendance,
  );
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

function canonicalRelayContext(
  evaluatorKeyId: string,
  ephemeralPublicKey: string,
  salt: string,
): string {
  return JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    evaluatorKeyId,
    ephemeralPublicKey,
    salt,
  });
}

async function sealEvaluatorRelayRequest(
  evaluatorKeyId: string,
  evaluatorPublicKey: string,
  capabilityToken: string,
  wrapper: Record<string, unknown>,
): Promise<{ relayRequest: EvaluatorRelayRequest; requestHash: string }> {
  const wrapperBytes = utf8(JSON.stringify(wrapper));
  if (
    wrapperBytes.length > RELAY_MAXIMUM_INNER_REQUEST_BYTES ||
    wrapperBytes.length + 4 > RELAY_PADDED_PLAINTEXT_BYTES
  ) {
    throw new ApiError(
      500,
      "evaluation_batch_too_large",
      "The private event evaluation request is too large.",
    );
  }
  const plaintext = new Uint8Array(RELAY_PADDED_PLAINTEXT_BYTES);
  new DataView(plaintext.buffer).setUint32(0, wrapperBytes.length, false);
  plaintext.set(wrapperBytes, 4);

  let evaluatorKey: CryptoKey;
  try {
    evaluatorKey = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer(base64UrlToBytes(evaluatorPublicKey)),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator encryption key is invalid.",
    );
  }
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const ephemeralPublicKey = bytesToBase64Url(
    new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey)),
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: evaluatorKey },
      ephemeral.privateKey,
      256,
    ),
  );
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const salt = bytesToBase64Url(saltBytes);
  const context = canonicalRelayContext(
    evaluatorKeyId,
    ephemeralPublicKey,
    salt,
  );
  const hkdfMaterial = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer(sharedSecret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: ownedArrayBuffer(saltBytes),
      info: ownedArrayBuffer(
        concatenateBytes(utf8(RELAY_KEY_INFO_LABEL), utf8(context)),
      ),
    },
    hkdfMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: ownedArrayBuffer(iv),
        additionalData: ownedArrayBuffer(
          concatenateBytes(utf8(RELAY_AAD_LABEL), utf8(context)),
        ),
        tagLength: 128,
      },
      aesKey,
      ownedArrayBuffer(plaintext),
    ),
  );
  const ciphertextBytes = concatenateBytes(iv, encrypted);
  if (ciphertextBytes.length !== RELAY_CIPHERTEXT_BYTES) {
    throw new ApiError(
      500,
      "evaluation_relay_unavailable",
      "The private event evaluation request could not be sealed.",
    );
  }
  const unsignedRequest = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    evaluatorKeyId,
    ephemeralPublicKey,
    salt,
    ciphertext: bytesToBase64Url(ciphertextBytes),
  };
  const capabilityKey = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer(utf8(capabilityToken)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const capabilityMac = bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        capabilityKey,
        ownedArrayBuffer(
          concatenateBytes(
            utf8(RELAY_CAPABILITY_LABEL),
            utf8(JSON.stringify(unsignedRequest)),
          ),
        ),
      ),
    ),
  );
  const relayRequest = { ...unsignedRequest, capabilityMac };
  return {
    relayRequest,
    requestHash: await sha256Base64Url(JSON.stringify(relayRequest)),
  };
}

async function acquireRelayEvaluationLease(
  db: D1Database,
  eventId: string,
  policyHash: string,
  batchHash: string,
  requestHash: string,
  leaseId: string,
  leaseExpiresAt: string,
  nowIso: string,
): Promise<boolean> {
  const acquired = await db
    .prepare(
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
         )`,
    )
    .bind(
      batchHash,
      requestHash,
      leaseId,
      leaseExpiresAt,
      nowIso,
      eventId,
      policyHash,
      nowIso,
    )
    .run();
  return (acquired.meta.changes ?? 0) === 1;
}

async function acquireEvaluationLease(
  db: D1Database,
  eventId: string,
  policyHash: string,
  nowIso: string,
): Promise<string | null> {
  const leaseId = crypto.randomUUID();
  const leaseExpiresAt = new Date(
    Date.parse(nowIso) + EVALUATION_LEASE_MILLISECONDS,
  ).toISOString();
  const acquired = await db
    .prepare(
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
         )`,
    )
    .bind(
      leaseId,
      leaseExpiresAt,
      nowIso,
      eventId,
      policyHash,
      nowIso,
    )
    .run();
  return (acquired.meta.changes ?? 0) === 1 ? leaseId : null;
}

async function resetEvaluationLease(
  db: D1Database,
  eventId: string,
  policyHash: string,
  leaseId: string,
): Promise<boolean> {
  const nowIso = new Date().toISOString();
  const released = await db
    .prepare(
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
         AND evaluation_lease_id = ?`,
    )
    .bind(nowIso, eventId, policyHash, leaseId)
    .run();
  return (released.meta.changes ?? 0) === 1;
}

/**
 * Releases only the still-active relay lease identified by all three frozen
 * identifiers. A stale scheduler or browser cannot clear a replacement lease.
 */
export async function releaseClientRelayEvaluationLease(
  db: D1Database,
  eventId: string,
  policyHash: string,
  leaseId: string,
): Promise<boolean> {
  return resetEvaluationLease(db, eventId, policyHash, leaseId);
}

export async function startClientRelayEvaluation(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  nowIso = new Date().toISOString(),
): Promise<EvaluationStartResult> {
  const relay = getEvaluatorRelayConfig(bindings);
  if (!event.invitationsSent || !event.privateResponsePolicy || !event.rsvpDeadline) {
    throw new ApiError(
      409,
      "evaluation_not_ready",
      "This event is not ready for private evaluation.",
    );
  }
  const policy = event.privateResponsePolicy;
  if (
    policy.evaluatorKeyId !== relay.evaluatorKeyId ||
    policy.evaluatorPublicKey !== relay.evaluatorPublicKey
  ) {
    throw new ApiError(
      503,
      "evaluation_key_unavailable",
      "The frozen event evaluator key is not available.",
    );
  }
  let row = await ensurePendingResolution(
    db,
    event.id,
    policy.policyHash,
    nowIso,
  );
  if (requiresDeadlineReveal(row, event, nowIso)) {
    await resetResolvedForReevaluation(db, event.id, policy.policyHash, nowIso);
    row = (await loadResolutionRow(db, event.id))!;
  }
  const existing = parseStoredResolution(row, event.id, policy.policyHash)!;
  if (existing.status !== "pending") {
    return { kind: "resolved", resolution: existing };
  }
  if (
    row.status === "evaluating" &&
    row.evaluationLeaseExpiresAt &&
    row.evaluationLeaseExpiresAt > nowIso
  ) {
    return { kind: "pending" };
  }

  const facts = await canonicalPolicyFacts(bindings, event, policy);
  const { batchHash, revealAttendance, slots } = await buildEvaluatorBatch(
    db,
    bindings,
    event,
    policy,
    facts,
    nowIso,
  );
  const relayRequestId = crypto.randomUUID();
  const leaseId = crypto.randomUUID();
  const expiresAt = new Date(
    Date.parse(nowIso) + RELAY_EVALUATION_LEASE_MILLISECONDS,
  ).toISOString();
  const evaluationRequest = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: event.id,
    policy: evaluatorPolicyDescriptor(policy),
    batchHash,
    revealAttendance,
    slots,
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
      evaluationRequest,
    },
  );
  const acquired = await acquireRelayEvaluationLease(
    db,
    event.id,
    policy.policyHash,
    batchHash,
    requestHash,
    leaseId,
    expiresAt,
    nowIso,
  );
  if (!acquired) {
    const current = await loadResolutionRow(db, event.id);
    const resolution = parseStoredResolution(current, event.id, policy.policyHash);
    return resolution && resolution.status !== "pending"
      ? { kind: "resolved", resolution }
      : { kind: "pending" };
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
      relayRequest,
    },
  };
}

function invalidRelayAttestation(): never {
  throw new ApiError(
    400,
    "invalid_evaluator_attestation",
    "The evaluator result could not be verified.",
  );
}

function canonicalUuid(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value,
    )
  ) {
    invalidRelayAttestation();
  }
  return value;
}

function canonicalIsoTimestamp(value: unknown): string {
  if (typeof value !== "string") invalidRelayAttestation();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRelayAttestation();
  }
  return value;
}

export async function completeClientRelayEvaluation(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  value: unknown,
  nowIso = new Date().toISOString(),
): Promise<EventResolution> {
  const relay = getEvaluatorRelayConfig(bindings);
  if (!event.invitationsSent || !event.privateResponsePolicy || !event.rsvpDeadline) {
    throw new ApiError(
      409,
      "evaluation_not_ready",
      "This event is not ready for private evaluation.",
    );
  }
  const policy = event.privateResponsePolicy;
  if (
    policy.evaluatorKeyId !== relay.evaluatorKeyId ||
    policy.evaluatorPublicKey !== relay.evaluatorPublicKey
  ) {
    throw new ApiError(
      503,
      "evaluation_key_unavailable",
      "The frozen event evaluator key is not available.",
    );
  }
  const row = await ensurePendingResolution(
    db,
    event.id,
    policy.policyHash,
    nowIso,
  );
  const existing = parseStoredResolution(row, event.id, policy.policyHash)!;
  if (existing.status !== "pending") return existing;
  if (
    row.status !== "evaluating" ||
    !row.batchHash ||
    !row.evaluationRequestHash ||
    !row.evaluationLeaseId ||
    !row.evaluationLeaseExpiresAt ||
    row.evaluationLeaseExpiresAt <= nowIso
  ) {
    throw new ApiError(
      409,
      "evaluation_lease_stale",
      "The evaluation lease is no longer active.",
    );
  }

  if (!isRecord(value)) invalidRelayAttestation();
  if (
    !hasExactKeys(value, [
      "protocolVersion",
      "relayRequestHash",
      "relayRequestId",
      "leaseId",
      "result",
      "attestation",
    ]) ||
    value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    !isCanonicalBase64UrlBytes(value.relayRequestHash, 32) ||
    value.relayRequestHash !== row.evaluationRequestHash
  ) {
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
    isRecord(value.result) && value.result.revealAttendance === true,
  );
  const canonicalResult = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    eventId: event.id,
    policyHash: policy.policyHash,
    batchHash: row.batchHash,
    evaluatorKeyId: policy.evaluatorKeyId,
    status: evaluatorResult.status,
    ...(evaluatorResult.legacyFormat
      ? {}
      : { revealAttendance: evaluatorResult.revealAttendance }),
    ...(evaluatorResult.status === "confirmed" && evaluatorResult.revealAttendance
      ? { attendingMemberIds: evaluatorResult.attendingMemberIds }
      : {}),
  };

  if (!isRecord(value.attestation)) invalidRelayAttestation();
  const attestation = value.attestation;
  if (
    !hasExactKeys(attestation, [
      "protocolVersion",
      "signingKeyId",
      "evaluatedAt",
      "canonicalDocument",
      "signature",
    ]) ||
    attestation.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    attestation.signingKeyId !== relay.resultSigningKeyId ||
    typeof attestation.canonicalDocument !== "string" ||
    attestation.canonicalDocument.length > 32_768 ||
    !isCanonicalBase64UrlBytes(attestation.signature, 64)
  ) {
    invalidRelayAttestation();
  }
  const evaluatedAt = canonicalIsoTimestamp(attestation.evaluatedAt);
  if (
    evaluatorResult.revealAttendance !== (evaluatedAt >= event.rsvpDeadline) ||
    evaluatedAt > row.evaluationLeaseExpiresAt ||
    Date.parse(evaluatedAt) > Date.parse(nowIso) + 30_000
  ) {
    invalidRelayAttestation();
  }
  const canonicalDocument = JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    signingKeyId: relay.resultSigningKeyId,
    relayRequestHash: row.evaluationRequestHash,
    relayRequestId,
    leaseId,
    evaluatedAt,
    result: canonicalResult,
  });
  if (attestation.canonicalDocument !== canonicalDocument) {
    invalidRelayAttestation();
  }
  let signingPublicKey: CryptoKey;
  try {
    signingPublicKey = await crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer(base64UrlToBytes(relay.resultSigningPublicKey)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator result signing key is invalid.",
    );
  }
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingPublicKey,
      ownedArrayBuffer(base64UrlToBytes(attestation.signature)),
      ownedArrayBuffer(utf8(canonicalDocument)),
    );
  } catch {
    invalidRelayAttestation();
  }
  if (!verified) invalidRelayAttestation();

  const attendingMemberIds =
    evaluatorResult.status === "confirmed" && evaluatorResult.revealAttendance
      ? JSON.stringify(evaluatorResult.attendingMemberIds)
      : null;
  const persisted = await db
    .prepare(
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
         AND evaluation_lease_expires_at > ?`,
    )
    .bind(
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
      nowIso,
    )
    .run();
  const finalRow = await loadResolutionRow(db, event.id);
  const finalResolution = parseStoredResolution(finalRow, event.id, policy.policyHash);
  if ((persisted.meta.changes ?? 0) !== 1) {
    if (finalResolution && finalResolution.status !== "pending") return finalResolution;
    throw new ApiError(
      409,
      "evaluation_lease_stale",
      "The evaluation lease is no longer active.",
    );
  }
  if (!finalResolution || finalResolution.status === "pending") {
    throw new ApiError(
      500,
      "event_resolution_unavailable",
      "The private event result could not be saved.",
    );
  }
  try {
    await sendResolutionTransitionNotifications(
      db,
      bindings,
      event,
      row.batchHash,
      evaluatorResult.status,
    );
  } catch (error) {
    reportEvaluationFailure(event.id, error);
  }
  return finalResolution;
}

export async function getEventResolutionForRead(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  nowIso = new Date().toISOString(),
): Promise<EventResolution | null> {
  if (!event.invitationsSent || !event.privateResponsePolicy) return null;
  if (!event.rsvpDeadline) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "A sent event is missing its reply deadline.",
    );
  }
  let row = await ensurePendingResolution(
    db,
    event.id,
    event.privateResponsePolicy.policyHash,
    nowIso,
  );
  if (requiresDeadlineReveal(row, event, nowIso)) {
    await resetResolvedForReevaluation(
      db,
      event.id,
      event.privateResponsePolicy.policyHash,
      nowIso,
    );
    row = (await loadResolutionRow(db, event.id))!;
  }
  const resolution = parseStoredResolution(
    row,
    event.id,
    event.privateResponsePolicy.policyHash,
  )!;
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
    nowIso,
  );
  if (!leaseId) {
    const current = await loadResolutionRow(db, event.id);
    return withRevealedGuestStates(
      db,
      event,
      parseStoredResolution(
        current,
        event.id,
        event.privateResponsePolicy.policyHash,
      ),
    );
  }

  try {
    const facts = await canonicalPolicyFacts(
      bindings,
      event,
      event.privateResponsePolicy,
    );
    const { batchHash, revealAttendance, slots } = await buildEvaluatorBatch(
      db,
      bindings,
      event,
      event.privateResponsePolicy,
      facts,
      nowIso,
    );
    const evaluatorResult = await callEvaluator(
      bindings,
      event,
      event.privateResponsePolicy,
      facts,
      batchHash,
      revealAttendance,
      slots,
    );
    const resolvedAt = new Date().toISOString();
    const attendingMemberIds =
      evaluatorResult.status === "confirmed" && evaluatorResult.revealAttendance
        ? JSON.stringify(evaluatorResult.attendingMemberIds)
        : null;
    await db
      .prepare(
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
           AND evaluation_lease_id = ?`,
      )
      .bind(
        evaluatorResult.status,
        batchHash,
        attendingMemberIds,
        resolvedAt,
        resolvedAt,
        event.id,
        event.privateResponsePolicy.policyHash,
        leaseId,
      )
      .run();
    const persisted = await loadResolutionRow(db, event.id);
    if (!persisted) {
      throw new ApiError(
        500,
        "event_resolution_unavailable",
        "The private event result could not be saved.",
      );
    }
    try {
      await sendResolutionTransitionNotifications(
        db,
        bindings,
        event,
        batchHash,
        evaluatorResult.status,
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
        event.privateResponsePolicy.policyHash,
      ),
    );
  } catch (error) {
    try {
      await resetEvaluationLease(
        db,
        event.id,
        event.privateResponsePolicy.policyHash,
        leaseId,
      );
    } catch {
      const resetError = new ApiError(
        503,
        "evaluation_lease_reset_failed",
        "The private event result is temporarily unavailable.",
      );
      reportEvaluationFailure(event.id, resetError);
      return { status: "pending", retrying: true };
    }
    reportEvaluationFailure(event.id, error);
    if (
      error instanceof ApiError &&
      ["event_policy_corrupt", "event_resolution_corrupt"].includes(error.code)
    ) {
      throw error;
    }
    return { status: "pending", retrying: true };
  }
}

export async function attachEventResolutions<T extends ResolutionReadableEvent>(
  db: D1Database,
  bindings: HerdBindings,
  events: T[],
): Promise<Array<T & { resolution: EventResolution | null }>> {
  const nowIso = new Date().toISOString();
  return Promise.all(
    events.map(async (event) => {
      try {
        let resolution = await getEventResolutionForRead(
          db,
          bindings,
          event,
          nowIso,
        );
        if (
          resolution?.status === "pending" &&
          getEvaluatorTransport(bindings) === "client_relay" &&
          (event as T & { role?: string }).role === "host"
        ) {
          resolution = { ...resolution, relayNeeded: true };
        }
        return {
          ...event,
          resolution,
        };
      } catch (error) {
        if (
          error instanceof ApiError &&
          [
            "event_evaluation_unavailable",
            "invalid_evaluator_response",
            "server_misconfigured",
          ].includes(error.code)
        ) {
          return {
            ...event,
            resolution:
              event.invitationsSent && event.privateResponsePolicy
                ? ({ status: "pending", retrying: true } as const)
                : null,
          };
        }
        throw error;
      }
    }),
  );
}
