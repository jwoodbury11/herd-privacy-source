import {
  bytesToBase64Url,
  PRIVATE_RESPONSE_CIPHER_SUITE,
  PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  type PrivateResponsePolicyV1,
} from "@/lib/privacy/protocol";
import type { HerdBindings } from "@/db";

import type { AuthConfig } from "./config";
import { signEventPolicy } from "./evaluator-trust";
import { ApiError } from "./http";
import type { CanonicalEvent } from "./types";

type EventPolicyRow = {
  protocolVersion: number;
  cipherSuite: string;
  policyHash: string;
  canonicalDocument: string;
  evaluatorKeyId: string;
  evaluatorPublicKey: string;
  evaluatorMeasurement: string;
  releaseId: string;
  paddedPlaintextBytes: number;
  frozenAt: string;
  policySigningKeyId: string | null;
  policySignature: string | null;
};

const EVENT_POLICY_SELECT = `SELECT
  protocol_version AS protocolVersion,
  cipher_suite AS cipherSuite,
  policy_hash AS policyHash,
  canonical_document AS canonicalDocument,
  evaluator_key_id AS evaluatorKeyId,
  evaluator_public_key AS evaluatorPublicKey,
  evaluator_measurement AS evaluatorMeasurement,
  release_id AS releaseId,
  padded_plaintext_bytes AS paddedPlaintextBytes,
  frozen_at AS frozenAt,
  policy_signing_key_id AS policySigningKeyId,
  policy_signature AS policySignature
FROM event_policies`;

function policyFromRow(row: EventPolicyRow | null): PrivateResponsePolicyV1 | null {
  if (!row) return null;
  if (
    row.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    row.cipherSuite !== PRIVATE_RESPONSE_CIPHER_SUITE ||
    row.paddedPlaintextBytes !== PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES
  ) {
    return null;
  }
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    policyHash: row.policyHash,
    canonicalDocument: row.canonicalDocument,
    evaluatorKeyId: row.evaluatorKeyId,
    evaluatorPublicKey: row.evaluatorPublicKey,
    evaluatorMeasurement: row.evaluatorMeasurement,
    releaseId: row.releaseId,
    paddedPlaintextBytes: PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES,
    frozenAt: row.frozenAt,
    policySigningKeyId: row.policySigningKeyId,
    policySignature: row.policySignature,
  };
}

export async function getPrivateResponsePolicy(
  db: D1Database,
  eventId: string,
): Promise<PrivateResponsePolicyV1 | null> {
  const row = await db
    .prepare(`${EVENT_POLICY_SELECT} WHERE event_id = ?`)
    .bind(eventId)
    .first<EventPolicyRow>();
  return policyFromRow(row);
}

export async function getPrivateResponsePolicies(
  db: D1Database,
  eventIds: string[],
): Promise<Map<string, PrivateResponsePolicyV1>> {
  if (eventIds.length === 0) return new Map();
  const placeholders = eventIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT
         event_id AS eventId,
         protocol_version AS protocolVersion,
         cipher_suite AS cipherSuite,
         policy_hash AS policyHash,
         canonical_document AS canonicalDocument,
         evaluator_key_id AS evaluatorKeyId,
         evaluator_public_key AS evaluatorPublicKey,
         evaluator_measurement AS evaluatorMeasurement,
         release_id AS releaseId,
         padded_plaintext_bytes AS paddedPlaintextBytes,
         frozen_at AS frozenAt,
         policy_signing_key_id AS policySigningKeyId,
         policy_signature AS policySignature
       FROM event_policies
       WHERE event_id IN (${placeholders})`,
    )
    .bind(...eventIds)
    .all<EventPolicyRow & { eventId: string }>();
  const policies = new Map<string, PrivateResponsePolicyV1>();
  for (const row of result.results) {
    const policy = policyFromRow(row);
    if (policy) policies.set(row.eventId, policy);
  }
  return policies;
}

export async function buildPrivateResponsePolicy(
  event: CanonicalEvent,
  config: AuthConfig,
  frozenAt: string,
  bindings?: HerdBindings,
): Promise<PrivateResponsePolicyV1> {
  const privateResponse = config.privateResponse;
  if (!privateResponse) {
    throw new ApiError(
      503,
      "private_responses_unavailable",
      "Private responses are temporarily unavailable.",
    );
  }
  // The signed policy is immutable and may outlive an invitee's account.
  // Membership therefore contains only opaque event-scoped IDs; names and
  // phone-derived values remain in deletable application records.
  const members = [...event.invitees]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((invitee) => ({ id: invitee.id }));
  const hostRequiredGroups = [...event.requiredGroups]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((group) => ({
      id: group.id,
      memberIDs: [...group.memberIDs].sort(),
    }));
  const document = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    event: {
      id: event.id,
      title: event.title,
      eventDate: event.eventDate,
      endDate: event.endDate,
      hostName: event.hostName,
      locationName: event.locationName,
      locationAddress: event.locationAddress,
      eventDescription: event.eventDescription,
    },
    members,
    hostRules: {
      minimumParticipants: event.minimumParticipants,
      requiredGroups: hostRequiredGroups,
    },
    rsvpDeadline: event.rsvpDeadline,
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits: {
      maximumParticipants: event.invitees.length + 1,
      maximumConditionGroups: event.invitees.length,
      maximumMembersPerGroup: event.invitees.length,
      paddedPlaintextBytes: PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES,
    },
    evaluator: {
      keyId: privateResponse.evaluatorKeyId,
      publicKey: privateResponse.evaluatorPublicKey,
      measurement: privateResponse.evaluatorMeasurement,
    },
    releaseId: privateResponse.releaseId,
  };
  const canonicalDocument = JSON.stringify(document);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalDocument),
  );
  const certification = bindings
    ? await signEventPolicy(bindings, canonicalDocument)
    : null;
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    cipherSuite: PRIVATE_RESPONSE_CIPHER_SUITE,
    policyHash: bytesToBase64Url(new Uint8Array(digest)),
    canonicalDocument,
    evaluatorKeyId: privateResponse.evaluatorKeyId,
    evaluatorPublicKey: privateResponse.evaluatorPublicKey,
    evaluatorMeasurement: privateResponse.evaluatorMeasurement,
    releaseId: privateResponse.releaseId,
    paddedPlaintextBytes: PRIVATE_RESPONSE_PADDED_PLAINTEXT_BYTES,
    frozenAt,
    policySigningKeyId: certification?.signingKeyId ?? null,
    policySignature: certification?.signature ?? null,
  };
}

export function prepareInsertPrivateResponsePolicy(
  db: D1Database,
  eventId: string,
  policy: PrivateResponsePolicyV1,
  epochFence: {
    evaluatorKeyEpochId: string;
    descriptorSha256: string;
  },
): D1PreparedStatement {
  if (policy.releaseId !== epochFence.evaluatorKeyEpochId) {
    throw new ApiError(
      503,
      "evaluator_epoch_changed",
      "The confidential evaluator changed before this event could be frozen.",
    );
  }
  return db
    .prepare(
      `INSERT OR IGNORE INTO event_policies
        (event_id, protocol_version, cipher_suite, policy_hash, canonical_document,
         evaluator_key_id, evaluator_public_key, evaluator_measurement, release_id,
         evaluator_epoch_descriptor_sha256, padded_plaintext_bytes, frozen_at,
         policy_signing_key_id, policy_signature)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      eventId,
      policy.protocolVersion,
      policy.cipherSuite,
      policy.policyHash,
      policy.canonicalDocument,
      policy.evaluatorKeyId,
      policy.evaluatorPublicKey,
      policy.evaluatorMeasurement,
      policy.releaseId,
      epochFence.descriptorSha256,
      policy.paddedPlaintextBytes,
      policy.frozenAt,
      policy.policySigningKeyId,
      policy.policySignature,
    );
}
