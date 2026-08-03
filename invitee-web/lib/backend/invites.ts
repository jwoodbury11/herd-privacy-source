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
import { pepperedHash, randomToken } from "./crypto";
import { requireEvaluatorEpochPolicyFence } from "./evaluator-epoch";
import { verifyStoredEventPolicyCertification } from "./evaluator-trust";
import { getEventById, toPublicEvent } from "./events";
import {
  ApiError,
  requireString,
} from "./http";
import { maskPhoneNumber, normalizePhoneNumber } from "./phone";
import {
  buildPrivateResponsePolicy,
  prepareInsertPrivateResponsePolicy,
} from "./policy";
import {
  getLatestValidResponseEnvelope,
  parseResponseEnvelope,
  RESPONSE_ENVELOPE_SELECT,
  responseEnvelopeHash,
  type ResponseEnvelopeRow,
} from "./response-envelopes";
import { ensurePrivateResponseReceipt } from "./response-transparency";
import {
  getEventResolutionForRead,
  prepareInsertPendingEventResolution,
} from "./resolutions";
import type { InviteAccess } from "./types";

const POKER_EVENT_ID = "10000000-0000-4000-8000-000000000001";
const POKER_INVITEE_IDS = {
  jeff: "20000000-0000-4000-8000-000000000001",
  alex: "20000000-0000-4000-8000-000000000002",
  maya: "20000000-0000-4000-8000-000000000003",
  daniel: "20000000-0000-4000-8000-000000000004",
  cody: "20000000-0000-4000-8000-000000000005",
  chase: "20000000-0000-4000-8000-000000000006",
  lucas: "20000000-0000-4000-8000-000000000007",
  matt: "20000000-0000-4000-8000-000000000008",
} as const;
const POKER_GROUP_ID = "30000000-0000-4000-8000-000000000001";

function futureFixtureDates(now = new Date()) {
  const eventDate = new Date(now.getTime() + 7 * 86_400_000);
  eventDate.setUTCMinutes(0, 0, 0);
  const endDate = new Date(eventDate.getTime() + 3 * 3_600_000);
  const rsvpDeadline = new Date(eventDate.getTime() - 2 * 86_400_000);
  return {
    eventDate: eventDate.toISOString(),
    endDate: endDate.toISOString(),
    rsvpDeadline: rsvpDeadline.toISOString(),
  };
}

async function ensureFixturePolicy(
  db: D1Database,
  bindings: HerdBindings,
  config: ReturnType<typeof getAuthConfig>,
): Promise<void> {
  const event = await getEventById(db, POKER_EVENT_ID);
  if (!event || event.privateResponsePolicy) return;
  const { hostUserId, ...canonicalEvent } = event;
  void hostUserId;
  const policy = await buildPrivateResponsePolicy(
    canonicalEvent,
    config,
    new Date().toISOString(),
    bindings,
  );
  const epochFence = await requireEvaluatorEpochPolicyFence(db, bindings);
  await db.batch([
    prepareInsertPrivateResponsePolicy(db, event.id, policy, epochFence),
    prepareInsertPendingEventResolution(
      db,
      event.id,
      policy.policyHash,
      policy.frozenAt,
    ),
  ]);
}

async function ensureTestHost(
  db: D1Database,
  bindings: HerdBindings,
  pepper: string,
  nowIso: string,
): Promise<string> {
  const hostPhone = normalizePhoneNumber(
    bindings.HERD_TEST_HOST_PHONE_E164 ?? "+14155550111",
  );
  const hostPhoneHash = await pepperedHash(pepper, "phone", hostPhone);
  await db
    .prepare(
      `INSERT INTO users
        (id, phone_number, phone_hash, name, address, created_at, updated_at)
       VALUES ('fixture_user_james', ?, ?, 'James', '', ?, ?)
       ON CONFLICT(phone_number) DO UPDATE SET
         phone_hash = excluded.phone_hash,
         name = CASE WHEN users.name = '' THEN 'James' ELSE users.name END,
         updated_at = excluded.updated_at`,
    )
    .bind(hostPhone, hostPhoneHash, nowIso, nowIso)
    .run();
  const host = await db
    .prepare("SELECT id FROM users WHERE phone_number = ?")
    .bind(hostPhone)
    .first<{ id: string }>();
  if (!host) {
    throw new ApiError(500, "fixture_unavailable", "The poker-party fixture is unavailable.");
  }
  return host.id;
}

export async function ensurePokerPartyFixture(
  db: D1Database,
  bindings: HerdBindings,
): Promise<void> {
  const config = getAuthConfig(bindings);
  if (!config.testBypassEnabled || !config.testPhoneNumber) {
    throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  }
  const now = new Date();
  const nowIso = now.toISOString();
  const hostUserId = await ensureTestHost(db, bindings, config.pepper, nowIso);
  const testPhone = config.testPhoneNumber!;
  const testPhoneHash = await pepperedHash(config.pepper, "phone", testPhone);
  const fixtureTokenHash = await pepperedHash(
    config.pepper,
    "invite-token",
    "poker-party",
  );
  const existing = await db
    .prepare(
      `SELECT event_date AS eventDate,
              location_name AS locationName,
              (SELECT phone_hash FROM invitees WHERE id = ?) AS fixturePhoneHash
       FROM events WHERE id = ?`,
    )
    .bind(POKER_INVITEE_IDS.jeff, POKER_EVENT_ID)
    .first<{
      eventDate: string | null;
      locationName: string;
      fixturePhoneHash: string | null;
    }>();

  if (!existing) {
    const dates = futureFixtureDates(now);
    const fixtureInvitees = [
      [POKER_INVITEE_IDS.jeff, "Jeff Wilson", testPhone, fixtureTokenHash],
      [POKER_INVITEE_IDS.alex, "Alex Smith", "+14155550112", null],
      [POKER_INVITEE_IDS.maya, "Maya Patel", "+16285550175", null],
      [POKER_INVITEE_IDS.daniel, "Daniel Stratton", "+14155550123", null],
      [POKER_INVITEE_IDS.cody, "Cody Morgan", "+15105550129", null],
      [POKER_INVITEE_IDS.chase, "Chase Haddleton", "+16505550153", null],
      [POKER_INVITEE_IDS.lucas, "Lucas Harrington", "+14155550162", null],
      [POKER_INVITEE_IDS.matt, "Matt Krisiloff", "+15105550190", null],
    ] as const;
    const statements: D1PreparedStatement[] = [
      db
        .prepare(
          `INSERT INTO events
            (id, host_user_id, title, event_date, end_date, host_name, location_name,
             location_address, minimum_participants, rsvp_deadline, event_description,
             invitations_sent, created_at, updated_at)
           VALUES (
             ?, ?, 'Poker night', ?, ?, 'James',
             'James’s place', 'San Francisco, CA', 4, ?,
             'A low-stakes poker night with pizza, drinks, and a firm ban on taking the game too seriously.',
             1, ?, ?
           )`,
        )
        .bind(
          POKER_EVENT_ID,
          hostUserId,
          dates.eventDate,
          dates.endDate,
          dates.rsvpDeadline,
          nowIso,
          nowIso,
        ),
    ];
    for (const [id, displayName, rawPhone, fixedTokenHash] of fixtureInvitees) {
      const phoneNumber = normalizePhoneNumber(rawPhone);
      const phoneHash = await pepperedHash(config.pepper, "phone", phoneNumber);
      const tokenHash =
        fixedTokenHash ??
        (await pepperedHash(config.pepper, "invite-token", randomToken(32)));
      statements.push(
        db
          .prepare(
            `INSERT INTO invitees
              (id, event_id, user_id, display_name, phone_number, phone_hash, token_hash,
               created_at, updated_at)
             VALUES (
               ?, ?,
               (SELECT id FROM users WHERE phone_hash = ? LIMIT 1),
               ?, ?, ?, ?, ?, ?
             )`,
          )
          .bind(
            id,
            POKER_EVENT_ID,
            phoneHash,
            displayName,
            phoneNumber,
            phoneHash,
            tokenHash,
            nowIso,
            nowIso,
          ),
      );
    }
    statements.push(
      db
        .prepare(
          `INSERT INTO groups (id, event_id, position)
           VALUES (?, ?, 0)`,
        )
        .bind(POKER_GROUP_ID, POKER_EVENT_ID),
      db
        .prepare(
          `INSERT INTO group_members (group_id, invitee_id, position)
           VALUES (?, ?, 0)`,
        )
        .bind(POKER_GROUP_ID, POKER_INVITEE_IDS.alex),
    );
    await db.batch(statements);
    await ensureFixturePolicy(db, bindings, config);
    return;
  }

  const eventTimestamp = existing.eventDate ? Date.parse(existing.eventDate) : 0;
  const fixturePolicyChanged =
    !Number.isFinite(eventTimestamp) ||
    eventTimestamp <= now.getTime() + 86_400_000 ||
    existing.locationName !== "James’s place" ||
    existing.fixturePhoneHash !== testPhoneHash;
  if (fixturePolicyChanged) {
    const dates = futureFixtureDates(now);
    await db.batch([
      db.prepare("DELETE FROM event_resolutions WHERE event_id = ?").bind(POKER_EVENT_ID),
      db.prepare("DELETE FROM response_envelopes WHERE event_id = ?").bind(POKER_EVENT_ID),
      db.prepare("DELETE FROM event_policies WHERE event_id = ?").bind(POKER_EVENT_ID),
      db
        .prepare(
          `UPDATE events
           SET event_date = ?, end_date = ?, rsvp_deadline = ?,
               location_name = 'James’s place', updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          dates.eventDate,
          dates.endDate,
          dates.rsvpDeadline,
          nowIso,
          POKER_EVENT_ID,
        ),
    ]);
  }
  await db
    .prepare(
      `UPDATE invitees
       SET phone_number = ?,
           phone_hash = ?,
           token_hash = ?,
           user_id = (SELECT id FROM users WHERE phone_hash = ? LIMIT 1),
           updated_at = ?
       WHERE id = ? AND event_id = ?`,
    )
    .bind(
      testPhone,
      testPhoneHash,
      fixtureTokenHash,
      testPhoneHash,
      nowIso,
      POKER_INVITEE_IDS.jeff,
      POKER_EVENT_ID,
    )
    .run();
  await db
    .prepare(
      `UPDATE events
       SET location_name = 'James’s place', updated_at = ?
       WHERE id = ?`,
    )
    .bind(nowIso, POKER_EVENT_ID)
    .run();
  await ensureFixturePolicy(db, bindings, config);
}

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
  if (token === "poker-party") await ensurePokerPartyFixture(db, bindings);
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
  const { hostUserId, ...canonicalEvent } = event;
  void hostUserId;
  const publicEvent = toPublicEvent(canonicalEvent);
  const resolution = await getEventResolutionForRead(
    db,
    bindings,
    canonicalEvent,
  );
  return {
    event: {
      ...publicEvent,
      resolution,
      invitees: publicEvent.invitees.map((invitee) => ({
        ...invitee,
        ...(canRespond && invitee.id === access.inviteeId
          ? { isCurrentUser: true }
          : {}),
      })),
      role: isHost ? ("host" as const) : ("invitee" as const),
      ...(!isHost ? { inviteToken: token } : {}),
      ...(canRespond
        ? {
            hasResponse: Boolean(responseEnvelope),
            responseRevision: responseEnvelope?.revision ?? null,
            accountKeyEpochId: session.accountKeyEpochId,
            accountKeyCommitment: session.accountKeyCommitment,
          }
        : {}),
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
            responseRevision: responseEnvelope?.revision ?? null,
            responseEnvelope,
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
  if (token === "poker-party") await ensurePokerPartyFixture(db, bindings);
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
  if (event.rsvpDeadline && event.rsvpDeadline <= new Date().toISOString()) {
    throw new ApiError(409, "rsvp_closed", "The reply deadline has passed.");
  }
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
  if (
    revisionRow &&
    (
      revisionRow.accountKeyEpochId !== envelope.accountKeyEpochId ||
      revisionRow.responseSigningPublicKey !== envelope.responseSigningPublicKey
    )
  ) {
    throw new ApiError(
      409,
      "response_authorization_locked",
      "This reply is locked to the account key that authorized its first saved revision. Starting over cannot replace it.",
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
             AND events.rsvp_deadline > ?
             AND event_policies.policy_hash = ?
             AND event_policies.evaluator_key_id = ?
             AND event_resolutions.policy_hash = event_policies.policy_hash
             AND event_resolutions.status = 'pending'
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
                 AND previous_response.account_key_epoch_id = ?
                 AND previous_response.response_signing_public_key = ?
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
        nowIso,
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
           events.rsvp_deadline AS rsvpDeadline,
           event_resolutions.status AS resolutionStatus,
           account_key_epochs.id AS activeAccountKeyEpochId,
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
        rsvpDeadline: string | null;
        resolutionStatus: string | null;
        activeAccountKeyEpochId: string | null;
        latestRevision: number;
      }>();
    if (
      !currentState?.rsvpDeadline ||
      currentState.rsvpDeadline <= nowIso ||
      currentState.resolutionStatus !== "pending"
    ) {
      throw new ApiError(409, "rsvp_closed", "The reply deadline has passed.");
    }
    if (currentState.activeAccountKeyEpochId !== envelope.accountKeyEpochId) {
      throw new ApiError(
        409,
        "account_key_epoch_changed",
        "The account encryption key changed. Refresh before responding.",
        { accountKeyEpochId: currentState.activeAccountKeyEpochId },
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
  return {
    responseEnvelope: saved,
    receipt: await ensurePrivateResponseReceipt(db, bindings, saved),
  };
}
