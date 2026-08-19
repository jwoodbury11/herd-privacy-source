import type { HerdBindings } from "@/db";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  normalizePrivateResponseEnvelope,
  verifyPrivateResponseAuthorizationSignature,
  type PrivateResponseEnvelopeV1,
  type PrivateResponseReceiptV1,
  type StoredPrivateResponseEnvelopeV1,
} from "@/lib/privacy/protocol";

import { getAuthenticatedSession } from "./auth";
import { getAuthConfig } from "./config";
import { pepperedHash } from "./crypto";
import { verifyStoredEventPolicyCertification } from "./evaluator-trust";
import {
  getEventById,
  getInviteeResponseHistories,
  getRespondedInviteeIdsByEvent,
  toPublicEvent,
} from "./events";
import {
  ApiError,
  requireString,
} from "./http";
import { maskPhoneNumber } from "./phone";
import {
  getLatestValidResponseEnvelope,
  parseResponseEnvelope,
  RESPONSE_ENVELOPE_SELECT,
  responseEnvelopeHash,
  type ResponseEnvelopeRow,
} from "./response-envelopes";
import { ensurePrivateResponseReceipt } from "./response-transparency";
import { getEventResolutionForRead } from "./resolutions";
import type { InviteAccess } from "./types";

async function findInviteAccess(
  db: D1Database,
  tokenHash: string,
): Promise<InviteAccess | null> {
  return db
    .prepare(
      `SELECT
         invitees.id AS inviteeId,
         invitees.event_id AS eventId,
         invitees.display_name AS displayName,
         invitees.phone_number AS phoneNumber,
         invitees.phone_hash AS phoneHash,
         events.host_user_id AS hostUserId
       FROM invitees
       JOIN events ON events.id = invitees.event_id
       WHERE invitees.token_hash = ?`,
    )
    .bind(tokenHash)
    .first<InviteAccess>();
}

async function responseCertificationStatus(
  db: D1Database,
  envelopeId: string,
): Promise<"certified" | "pending"> {
  const certification = await db
    .prepare(
      `SELECT entries.receipt_signature AS receiptSignature,
              entries.signed_at AS signedAt,
              heads.signature AS headSignature,
              heads.generated_at AS headGeneratedAt
       FROM response_transparency_entries AS entries
       LEFT JOIN response_transparency_heads AS heads
         ON heads.log_index = entries.log_index
       WHERE entries.envelope_id = ?`,
    )
    .bind(envelopeId)
    .first<{
      receiptSignature: string | null;
      signedAt: string | null;
      headSignature: string | null;
      headGeneratedAt: string | null;
    }>();
  return certification?.receiptSignature &&
    certification.signedAt &&
    certification.headSignature &&
    certification.headGeneratedAt
    ? "certified"
    : "pending";
}

export async function getInviteByToken(
  request: Request,
  db: D1Database,
  bindings: HerdBindings,
  rawToken: string,
) {
  const token = requireString(rawToken, "invite token", { min: 8, max: 200 });
  if (!/^[A-Za-z0-9_-]+$/.test(token)) {
    throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  }
  const config = getAuthConfig(bindings);
  const tokenHash = await pepperedHash(config.pepper, "invite-token", token);
  const access = await findInviteAccess(db, tokenHash);
  if (!access) throw new ApiError(404, "invite_not_found", "The invitation was not found.");

  const session = await getAuthenticatedSession(request, {
    required: false,
    db,
    bindings,
  });
  const sessionPhoneHash = session
    ? await pepperedHash(config.pepper, "phone", session.user.phoneNumber)
    : null;
  const isInvitee = Boolean(sessionPhoneHash && sessionPhoneHash === access.phoneHash);
  const isHost = session?.user.id === access.hostUserId;
  const canRespond = isInvitee && !isHost;
  if (session && !isInvitee && !isHost) {
    throw new ApiError(
      403,
      "invite_for_different_account",
      "This invitation belongs to a different phone number.",
    );
  }

  const event = await getEventById(db, access.eventId);
  if (!event) throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  if (!session) {
    return {
      invitationPreview: {
        eventId: event.id,
        title: event.title,
        hostName: event.hostName,
        eventDate: event.eventDate,
        phoneNumberMasked: maskPhoneNumber(access.phoneNumber),
        requiresAuthentication: true,
      },
    };
  }
  const responseEnvelope =
    canRespond
      ? await getLatestValidResponseEnvelope(db, access.inviteeId)
      : null;
  const certificationStatus = responseEnvelope
    ? await responseCertificationStatus(db, responseEnvelope.envelopeId)
    : null;
  const { hostUserId, ...canonicalEvent } = event;
  void hostUserId;
  const publicEvent = toPublicEvent(canonicalEvent);
  const respondedInviteeIds = isHost || canRespond
    ? (await getRespondedInviteeIdsByEvent(db, bindings, [canonicalEvent.id])).get(canonicalEvent.id)
      ?? new Set<string>()
    : new Set<string>();
  const hasBallot = canRespond && respondedInviteeIds.has(access.inviteeId);
  const canViewResponseProgress = isHost || Boolean(responseEnvelope) || hasBallot;
  const resolution = await getEventResolutionForRead(
    db,
    bindings,
    canonicalEvent,
  );
  const projectedEvent = {
      ...publicEvent,
      resolution,
      invitees: publicEvent.invitees.map((invitee) => ({
        ...invitee,
        ...(canRespond && invitee.id === access.inviteeId
          ? { isCurrentUser: true }
          : {}),
        ...(canViewResponseProgress
          ? { hasResponded: respondedInviteeIds.has(invitee.id) }
          : {}),
      })),
      role: isHost ? ("host" as const) : ("invitee" as const),
      ...(!isHost ? { inviteToken: token } : {}),
      ...(canRespond
        ? {
            hasResponse: Boolean(responseEnvelope),
            hasBallot,
            responseRevision: responseEnvelope?.revision ?? null,
            responseCertificationStatus: certificationStatus,
            accountKeyEpochId: session.accountKeyEpochId,
            accountKeyCommitment: session.accountKeyCommitment,
          }
        : {}),
  };
  const responseHistories = await getInviteeResponseHistories(db, [projectedEvent]);
  return {
    event: {
      ...projectedEvent,
      invitees: projectedEvent.invitees.map((invitee) => ({
        ...invitee,
        responseHistory: responseHistories.get(`${projectedEvent.id}:${invitee.id}`),
      })),
    },
    inviteMetadata: {
      id: access.inviteeId,
      displayName: access.displayName,
      phoneNumberMasked: maskPhoneNumber(access.phoneNumber),
      authenticated: isInvitee || isHost,
      canRespond,
      requiresAuthentication: !isInvitee && !isHost,
      ...(canRespond
        ? {
            accountKeyEpochId: session.accountKeyEpochId,
            accountKeyCommitment: session.accountKeyCommitment,
            hasResponse: Boolean(responseEnvelope),
            hasBallot,
            responseRevision: responseEnvelope?.revision ?? null,
            responseEnvelope,
            responseCertificationStatus: certificationStatus,
          }
        : {}),
    },
  };
}

const FORBIDDEN_PLAINTEXT_RESPONSE_FIELDS = new Set([
  "response",
  "reply",
  "minimumParticipants",
  "conditionGroups",
  "requiredGroups",
]);

function normalizeSubmittedEnvelope(
  payload: Record<string, unknown>,
): PrivateResponseEnvelopeV1 {
  for (const field of FORBIDDEN_PLAINTEXT_RESPONSE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(payload, field)) {
      throw new ApiError(
        400,
        "plaintext_response_rejected",
        "Herd accepts only encrypted response envelopes.",
      );
    }
  }
  if (
    Object.keys(payload).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(payload, "envelope")
  ) {
    throw new ApiError(
      400,
      "invalid_response_envelope",
      "The request must contain only an encrypted envelope.",
    );
  }
  const rawEnvelope = payload.envelope;
  if (rawEnvelope && typeof rawEnvelope === "object" && !Array.isArray(rawEnvelope)) {
    for (const field of FORBIDDEN_PLAINTEXT_RESPONSE_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(rawEnvelope, field)) {
        throw new ApiError(
          400,
          "plaintext_response_rejected",
          "Herd accepts only encrypted response envelopes.",
        );
      }
    }
  }
  try {
    const envelope = normalizePrivateResponseEnvelope(rawEnvelope);
    for (const encoded of [
      envelope.policyHash,
      envelope.payloadCiphertext,
      envelope.userKeyWrap,
      envelope.evaluatorKeyWrap,
      envelope.responseSigningPublicKey,
      envelope.responseSignature,
    ]) {
      if (bytesToBase64Url(base64UrlToBytes(encoded)) !== encoded) {
        throw new TypeError("Non-canonical base64url encoding.");
      }
    }
    if (base64UrlToBytes(envelope.evaluatorKeyWrap)[0] !== 0x04) {
      throw new TypeError("Evaluator wrap must contain an uncompressed P-256 key.");
    }
    return envelope;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      400,
      "invalid_response_envelope",
      error instanceof Error ? error.message : "The encrypted response is invalid.",
    );
  }
}

export async function putInviteRsvp(
  request: Request,
  db: D1Database,
  bindings: HerdBindings,
  rawToken: string,
  payload: Record<string, unknown>,
): Promise<{
  responseEnvelope: StoredPrivateResponseEnvelopeV1;
  receipt: PrivateResponseReceiptV1;
}> {
  const token = requireString(rawToken, "invite token", { min: 8, max: 200 });
  if (!/^[A-Za-z0-9_-]+$/.test(token)) {
    throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  }
  const envelope = normalizeSubmittedEnvelope(payload);
  const config = getAuthConfig(bindings);
  const tokenHash = await pepperedHash(config.pepper, "invite-token", token);
  const access = await findInviteAccess(db, tokenHash);
  if (!access) throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  const session = await getAuthenticatedSession(request, { db, bindings });
  if (session!.user.id === access.hostUserId) {
    throw new ApiError(
      403,
      "host_cannot_respond",
      "The event host cannot respond through an invitation.",
    );
  }
  const sessionPhoneHash = await pepperedHash(
    config.pepper,
    "phone",
    session!.user.phoneNumber,
  );
  if (sessionPhoneHash !== access.phoneHash) {
    throw new ApiError(
      403,
      "invite_for_different_account",
      "This invitation belongs to a different phone number.",
    );
  }
  const ciphertextHash = await responseEnvelopeHash(envelope);
  if (!(await verifyPrivateResponseAuthorizationSignature(envelope, ciphertextHash))) {
    throw new ApiError(
      400,
      "invalid_response_authorization",
      "The encrypted response is missing a valid device authorization.",
    );
  }
  const exactRetryRow = await db
    .prepare(
      `${RESPONSE_ENVELOPE_SELECT}
       WHERE invitee_id = ? AND revision = ?`,
    )
    .bind(access.inviteeId, envelope.revision)
    .first<ResponseEnvelopeRow>();
  const exactRetry = parseResponseEnvelope(exactRetryRow);
  if (exactRetryRow && !exactRetry) {
    throw new ApiError(
      500,
      "response_envelope_corrupt",
      "The existing encrypted response could not be validated.",
    );
  }
  if (exactRetry?.ciphertextHash === ciphertextHash) {
    return {
      responseEnvelope: exactRetry,
      receipt: await ensurePrivateResponseReceipt(db, bindings, exactRetry),
    };
  }
  if (!session!.accountKeyCommitment) {
    throw new ApiError(
      409,
      "account_key_not_initialized",
      "Initialize this device encryption key before responding.",
    );
  }

  const event = await getEventById(db, access.eventId);
  if (!event) throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  if (!event.privateResponsePolicy) {
    throw new ApiError(
      409,
      "event_policy_not_frozen",
      "This event is not ready to accept private responses.",
    );
  }
  if (!(await verifyStoredEventPolicyCertification(bindings, event.privateResponsePolicy))) {
    throw new ApiError(
      500,
      "event_policy_corrupt",
      "The frozen event policy could not be certified.",
    );
  }
  const currentResolution = await db
    .prepare(
      `SELECT status
       FROM event_resolutions
       WHERE event_id = ? AND policy_hash = ?`,
    )
    .bind(event.id, event.privateResponsePolicy.policyHash)
    .first<{ status: string }>();
  if (currentResolution?.status === "confirmed") {
    throw new ApiError(
      409,
      "event_already_confirmed",
      "Responses cannot be changed after an event is confirmed.",
    );
  }
  if (envelope.eventId !== event.id || envelope.eventId !== access.eventId) {
    throw new ApiError(409, "response_event_mismatch", "The response is for another event.");
  }
  if (envelope.inviteeId !== access.inviteeId) {
    throw new ApiError(
      409,
      "response_invitee_mismatch",
      "The response is for another invitation.",
    );
  }
  if (envelope.policyHash !== event.privateResponsePolicy.policyHash) {
    throw new ApiError(
      409,
      "response_policy_changed",
      "The event policy changed. Refresh before responding.",
    );
  }
  if (envelope.evaluatorKeyId !== event.privateResponsePolicy.evaluatorKeyId) {
    throw new ApiError(
      409,
      "response_evaluator_mismatch",
      "The response uses an unapproved evaluator key.",
    );
  }
  if (envelope.accountKeyEpochId !== session!.accountKeyEpochId) {
    throw new ApiError(
      409,
      "account_key_epoch_changed",
      "The account encryption key changed. Refresh before responding.",
      { accountKeyEpochId: session!.accountKeyEpochId },
    );
  }
  const revisionRow = await db
    .prepare(
      `SELECT revision, account_key_epoch_id AS accountKeyEpochId,
              response_signing_public_key AS responseSigningPublicKey
       FROM response_envelopes
       WHERE invitee_id = ?
       ORDER BY revision DESC
       LIMIT 1`,
    )
    .bind(access.inviteeId)
    .first<{
      revision: number;
      accountKeyEpochId: string;
      responseSigningPublicKey: string | null;
    }>();
  const expectedRevision = (revisionRow?.revision ?? 0) + 1;
  if (envelope.revision !== expectedRevision) {
    throw new ApiError(
      409,
      "response_revision_conflict",
      "The response changed on another device. Refresh and try again.",
      { expectedRevision },
    );
  }
  const accountEpochChanged = Boolean(
    revisionRow && revisionRow.accountKeyEpochId !== envelope.accountKeyEpochId,
  );
  const responseSignerChanged = Boolean(
    revisionRow &&
      revisionRow.responseSigningPublicKey !== envelope.responseSigningPublicKey,
  );
  if (revisionRow && accountEpochChanged !== responseSignerChanged) {
    throw new ApiError(
      409,
      "response_authorization_locked",
      "The response key and private-reply key must switch together.",
    );
  }

  const nowIso = new Date().toISOString();
  let savedResult: D1Result;
  try {
    savedResult = await db
      .prepare(
        `INSERT INTO response_envelopes
          (id, event_id, invitee_id, account_key_epoch_id, policy_hash,
           protocol_version, cipher_suite, evaluator_key_id, revision,
           payload_ciphertext, user_key_wrap, evaluator_key_wrap,
           response_signing_public_key, response_signature, ciphertext_hash,
           created_at, updated_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
           SELECT 1
           FROM invitees
           JOIN events ON events.id = invitees.event_id
           JOIN event_policies ON event_policies.event_id = events.id
           JOIN event_resolutions ON event_resolutions.event_id = events.id
           JOIN account_key_epochs ON account_key_epochs.id = ?
           WHERE invitees.id = ?
             AND invitees.event_id = ?
             AND invitees.phone_hash = ?
             AND invitees.user_id = ?
             AND events.invitations_sent = 1
             AND event_policies.policy_hash = ?
             AND event_policies.evaluator_key_id = ?
             AND event_resolutions.policy_hash = event_policies.policy_hash
             AND event_resolutions.status <> 'confirmed'
             AND account_key_epochs.user_id = invitees.user_id
             AND account_key_epochs.superseded_at IS NULL
             AND account_key_epochs.key_commitment = ?
         )
           AND ? = COALESCE(
             (SELECT MAX(revision) FROM response_envelopes WHERE invitee_id = ?),
             0
           ) + 1
           AND (
             ? = 1 OR EXISTS (
               SELECT 1
               FROM response_envelopes AS previous_response
               WHERE previous_response.invitee_id = ?
                 AND previous_response.revision = ? - 1
                 AND (
                   (previous_response.account_key_epoch_id = ?
                     AND previous_response.response_signing_public_key = ?)
                   OR
                   (previous_response.account_key_epoch_id <> ?
                     AND previous_response.response_signing_public_key <> ?)
                 )
             )
           )
         ON CONFLICT DO NOTHING`,
      )
      .bind(
        envelope.envelopeId,
        access.eventId,
        access.inviteeId,
        envelope.accountKeyEpochId,
        envelope.policyHash,
        envelope.protocolVersion,
        envelope.cipherSuite,
        envelope.evaluatorKeyId,
        envelope.revision,
        envelope.payloadCiphertext,
        envelope.userKeyWrap,
        envelope.evaluatorKeyWrap,
        envelope.responseSigningPublicKey,
        envelope.responseSignature,
        ciphertextHash,
        nowIso,
        nowIso,
        envelope.accountKeyEpochId,
        access.inviteeId,
        access.eventId,
        access.phoneHash,
        session!.user.id,
        envelope.policyHash,
        envelope.evaluatorKeyId,
        session!.accountKeyCommitment,
        envelope.revision,
        access.inviteeId,
        envelope.revision,
        access.inviteeId,
        envelope.revision,
        envelope.accountKeyEpochId,
        envelope.responseSigningPublicKey,
        envelope.accountKeyEpochId,
        envelope.responseSigningPublicKey,
      )
      .run();
  } catch {
    throw new ApiError(
      409,
      "response_revision_conflict",
      "The response changed on another device. Refresh and try again.",
    );
  }
  if ((savedResult.meta.changes ?? 0) !== 1) {
    const concurrentRow = await db
      .prepare(
        `${RESPONSE_ENVELOPE_SELECT}
         WHERE invitee_id = ? AND revision = ?`,
      )
      .bind(access.inviteeId, envelope.revision)
      .first<ResponseEnvelopeRow>();
    const concurrent = parseResponseEnvelope(concurrentRow);
    if (concurrent?.ciphertextHash === ciphertextHash) {
      return {
        responseEnvelope: concurrent,
        receipt: await ensurePrivateResponseReceipt(db, bindings, concurrent),
      };
    }
    const currentState = await db
      .prepare(
         `SELECT
           account_key_epochs.id AS activeAccountKeyEpochId,
           event_resolutions.status AS resolutionStatus,
           COALESCE(
             (SELECT MAX(revision) FROM response_envelopes WHERE invitee_id = ?),
             0
           ) AS latestRevision
         FROM events
         LEFT JOIN event_resolutions ON event_resolutions.event_id = events.id
         LEFT JOIN account_key_epochs
           ON account_key_epochs.user_id = ? AND account_key_epochs.superseded_at IS NULL
         WHERE events.id = ?`,
      )
      .bind(access.inviteeId, session!.user.id, access.eventId)
      .first<{
        activeAccountKeyEpochId: string | null;
        resolutionStatus: string | null;
        latestRevision: number;
      }>();
    if (!currentState) {
      throw new ApiError(404, "invite_not_found", "The invitation was not found.");
    }
    if (currentState.activeAccountKeyEpochId !== envelope.accountKeyEpochId) {
      throw new ApiError(
        409,
        "account_key_epoch_changed",
        "The account encryption key changed. Refresh before responding.",
        { accountKeyEpochId: currentState.activeAccountKeyEpochId },
      );
    }
    if (currentState.resolutionStatus === "confirmed") {
      throw new ApiError(
        409,
        "event_already_confirmed",
        "Responses cannot be changed after an event is confirmed.",
      );
    }
    throw new ApiError(
      409,
      "response_revision_conflict",
      "The response changed on another device. Refresh and try again.",
      { expectedRevision: (currentState.latestRevision ?? 0) + 1 },
    );
  }
  const saved = parseResponseEnvelope(
    await db
      .prepare(
        `${RESPONSE_ENVELOPE_SELECT}
         WHERE invitee_id = ? AND revision = ?`,
      )
      .bind(access.inviteeId, envelope.revision)
      .first<ResponseEnvelopeRow>(),
  );
  if (!saved) {
    throw new ApiError(
      500,
      "response_save_failed",
      "The encrypted response could not be saved.",
    );
  }
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
    .bind(nowIso, access.eventId, envelope.policyHash)
    .run();
  return {
    responseEnvelope: saved,
    receipt: await ensurePrivateResponseReceipt(db, bindings, saved),
  };
}
