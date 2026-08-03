import { getActiveAccountKeyEpoch } from "./account-keys";
import { getAuthConfig } from "./config";
import { pepperedHash } from "./crypto";
import { requireEvaluatorEpochPolicyFence } from "./evaluator-epoch";
import { ApiError, requireString, requireUuid } from "./http";
import {
  assertInvitationDeliveryReady,
  dispatchEventInvitations,
  getInvitationDeliverySummaries,
  prepareInvitationDeliveryStatements,
} from "./invitation-delivery";
import { createSealedInviteToken, openSealedInviteToken } from "./invite-tokens";
import { normalizePhoneNumber } from "./phone";
import {
  buildPrivateResponsePolicy,
  getPrivateResponsePolicies,
  getPrivateResponsePolicy,
  prepareInsertPrivateResponsePolicy,
} from "./policy";
import { prepareInsertPendingEventResolution } from "./resolutions";
import type {
  CanonicalEvent,
  CanonicalInvitee,
  CanonicalRequiredGroup,
  HerdUser,
  PublicEvent,
} from "./types";

type EventRow = {
  id: string;
  hostUserId: string;
  title: string;
  eventDate: string | null;
  endDate: string | null;
  hostName: string;
  locationName: string;
  locationAddress: string;
  minimumParticipants: number;
  rsvpDeadline: string | null;
  eventDescription: string;
  invitationsSent: number | boolean;
  createdAt: string;
  updatedAt: string;
};

type InviteeRow = CanonicalInvitee & {
  eventId: string;
  phoneHash: string;
  tokenHash: string;
  tokenCiphertext: string | null;
  tokenNonce: string | null;
  tokenStorageVersion: number | null;
};

type GroupMemberRow = {
  id: string;
  eventId: string;
  position: number;
  inviteeId: string | null;
  memberPosition: number | null;
};

type ValidatedEvent = Omit<
  CanonicalEvent,
  "createdAt" | "privateResponsePolicy" | "invitationDelivery"
> & {
  createdAt: string | null;
};

const EVENT_SELECT = `SELECT
  id,
  host_user_id AS hostUserId,
  title,
  event_date AS eventDate,
  end_date AS endDate,
  host_name AS hostName,
  location_name AS locationName,
  location_address AS locationAddress,
  minimum_participants AS minimumParticipants,
  rsvp_deadline AS rsvpDeadline,
  event_description AS eventDescription,
  invitations_sent AS invitationsSent,
  created_at AS createdAt,
  updated_at AS updatedAt
FROM events`;

function normalizeIsoDate(
  value: unknown,
  field: string,
  options: { nullable?: boolean } = {},
): string | null {
  if ((value === undefined || value === null) && options.nullable) return null;
  if (typeof value !== "string" || !value.trim()) {
    throw new ApiError(
      400,
      "invalid_event",
      `${field} must be an ISO 8601 timestamp${options.nullable ? " or null" : ""}.`,
    );
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new ApiError(400, "invalid_event", `${field} must be an ISO 8601 timestamp.`);
  }
  return new Date(timestamp).toISOString();
}

function requireInteger(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new ApiError(
      400,
      "invalid_event",
      `${field} must be an integer from ${minimum} to ${maximum}.`,
    );
  }
  return value as number;
}

export function validateCanonicalEvent(
  value: unknown,
  expectedId: string,
): ValidatedEvent {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, "invalid_event", "event must be a JSON object.");
  }
  const input = value as Record<string, unknown>;
  const id = requireUuid(input.id, "event.id");
  if (id !== expectedId) {
    throw new ApiError(400, "event_id_mismatch", "The event ID must match the URL.");
  }
  const title = requireString(input.title, "event.title", { max: 120 });
  const hostName = requireString(input.hostName, "event.hostName", { max: 80 });
  const locationName = requireString(input.locationName, "event.locationName", {
    max: 160,
    allowEmpty: true,
  });
  const locationAddress = requireString(
    input.locationAddress,
    "event.locationAddress",
    { max: 300, allowEmpty: true },
  );
  const eventDescription = requireString(
    input.eventDescription,
    "event.eventDescription",
    { max: 2_000, allowEmpty: true },
  );
  const eventDate = normalizeIsoDate(input.eventDate, "event.eventDate", {
    nullable: true,
  });
  const endDate = normalizeIsoDate(input.endDate, "event.endDate", { nullable: true });
  const rsvpDeadline = normalizeIsoDate(input.rsvpDeadline, "event.rsvpDeadline", {
    nullable: true,
  });
  const createdAt =
    input.createdAt === undefined
      ? null
      : normalizeIsoDate(input.createdAt, "event.createdAt", { nullable: true });
  if (eventDate && endDate && endDate <= eventDate) {
    throw new ApiError(400, "invalid_event", "event.endDate must be after event.eventDate.");
  }
  if (eventDate && rsvpDeadline && rsvpDeadline >= eventDate) {
    throw new ApiError(
      400,
      "invalid_event",
      "event.rsvpDeadline must be before event.eventDate.",
    );
  }

  if (!Array.isArray(input.invitees) || input.invitees.length > 19) {
    throw new ApiError(400, "invalid_event", "event.invitees must contain at most 19 people.");
  }
  const inviteeIds = new Set<string>();
  const inviteePhones = new Set<string>();
  const invitees = input.invitees.map((value, index): CanonicalInvitee => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ApiError(400, "invalid_event", `event.invitees[${index}] is invalid.`);
    }
    const invitee = value as Record<string, unknown>;
    const inviteeId = requireUuid(invitee.id, `event.invitees[${index}].id`);
    const phoneNumber = normalizePhoneNumber(invitee.phoneNumber);
    if (inviteeIds.has(inviteeId) || inviteePhones.has(phoneNumber)) {
      throw new ApiError(
        400,
        "invalid_event",
        "Each invitee ID and phone number must be unique within an event.",
      );
    }
    inviteeIds.add(inviteeId);
    inviteePhones.add(phoneNumber);
    return {
      id: inviteeId,
      displayName: requireString(
        invitee.displayName,
        `event.invitees[${index}].displayName`,
        { max: 80 },
      ),
      phoneNumber,
    };
  });

  const minimumParticipants = requireInteger(
    input.minimumParticipants,
    "event.minimumParticipants",
    2,
    50,
  );
  if (invitees.length > 0 && minimumParticipants > invitees.length + 1) {
    throw new ApiError(
      400,
      "invalid_event",
      "event.minimumParticipants cannot exceed the host plus invited people.",
    );
  }

  if (!Array.isArray(input.requiredGroups) || input.requiredGroups.length > 19) {
    throw new ApiError(
      400,
      "invalid_event",
      "event.requiredGroups must contain at most 19 groups.",
    );
  }
  const groupIds = new Set<string>();
  const groupedInviteeIds = new Set<string>();
  const requiredGroups = input.requiredGroups.map(
    (value, index): CanonicalRequiredGroup => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new ApiError(
          400,
          "invalid_event",
          `event.requiredGroups[${index}] is invalid.`,
        );
      }
      const group = value as Record<string, unknown>;
      const groupId = requireUuid(group.id, `event.requiredGroups[${index}].id`);
      if (groupIds.has(groupId)) {
        throw new ApiError(400, "invalid_event", "Required-group IDs must be unique.");
      }
      groupIds.add(groupId);
      if (
        !Array.isArray(group.memberIDs) ||
        group.memberIDs.length === 0 ||
        group.memberIDs.length > 19
      ) {
        throw new ApiError(
          400,
          "invalid_event",
          "Each required group must contain at least one invitee.",
        );
      }
      const memberIDs = group.memberIDs.map((memberId, memberIndex) =>
        requireUuid(
          memberId,
          `event.requiredGroups[${index}].memberIDs[${memberIndex}]`,
        ),
      );
      if (
        new Set(memberIDs).size !== memberIDs.length ||
        memberIDs.some((memberId) => groupedInviteeIds.has(memberId)) ||
        memberIDs.some((memberId) => !inviteeIds.has(memberId))
      ) {
        throw new ApiError(
          400,
          "invalid_event",
          "Required groups may reference each invitee at most once across the event.",
        );
      }
      memberIDs.forEach((memberId) => groupedInviteeIds.add(memberId));
      return { id: groupId, memberIDs };
    },
  );

  if (typeof input.invitationsSent !== "boolean") {
    throw new ApiError(400, "invalid_event", "event.invitationsSent must be boolean.");
  }
  if (
    input.invitationsSent &&
    (invitees.length === 0 || minimumParticipants > invitees.length + 1)
  ) {
    throw new ApiError(
      400,
      "invalid_event",
      "A sent event must invite enough people to satisfy its minimum.",
    );
  }
  if (input.invitationsSent && (!eventDate || !rsvpDeadline)) {
    throw new ApiError(
      400,
      "invalid_event",
      "A sent event must have an event date and reply deadline.",
    );
  }

  return {
    id,
    title,
    eventDate,
    endDate,
    hostName,
    locationName,
    locationAddress,
    invitees,
    minimumParticipants,
    requiredGroups,
    rsvpDeadline,
    eventDescription,
    createdAt,
    invitationsSent: input.invitationsSent,
  };
}

async function hydrateEvents(
  db: D1Database,
  eventRows: EventRow[],
): Promise<CanonicalEvent[]> {
  if (eventRows.length === 0) return [];
  const placeholders = eventRows.map(() => "?").join(", ");
  const eventIds = eventRows.map((event) => event.id);
  const [inviteeResult, groupResult, policiesByEvent, deliveriesByEvent] = await Promise.all([
    db
      .prepare(
        `SELECT id,
                event_id AS eventId,
                display_name AS displayName,
                phone_number AS phoneNumber,
                phone_hash AS phoneHash,
                token_hash AS tokenHash,
                token_ciphertext AS tokenCiphertext,
                token_nonce AS tokenNonce,
                token_storage_version AS tokenStorageVersion
         FROM invitees
         WHERE event_id IN (${placeholders})
         ORDER BY created_at ASC, id ASC`,
      )
      .bind(...eventIds)
      .all<InviteeRow>(),
    db
      .prepare(
        `SELECT groups.id,
                groups.event_id AS eventId,
                groups.position,
                group_members.invitee_id AS inviteeId,
                group_members.position AS memberPosition
         FROM groups
         LEFT JOIN group_members ON group_members.group_id = groups.id
         WHERE groups.event_id IN (${placeholders})
         ORDER BY groups.position ASC, group_members.position ASC`,
      )
      .bind(...eventIds)
      .all<GroupMemberRow>(),
    getPrivateResponsePolicies(db, eventIds),
    getInvitationDeliverySummaries(db, eventIds),
  ]);
  const inviteesByEvent = new Map<string, CanonicalInvitee[]>();
  for (const invitee of inviteeResult.results) {
    const values = inviteesByEvent.get(invitee.eventId) ?? [];
    values.push({
      id: invitee.id,
      displayName: invitee.displayName,
      phoneNumber: invitee.phoneNumber,
    });
    inviteesByEvent.set(invitee.eventId, values);
  }
  const groupsByEvent = new Map<string, Map<string, CanonicalRequiredGroup>>();
  for (const groupRow of groupResult.results) {
    const eventGroups =
      groupsByEvent.get(groupRow.eventId) ?? new Map<string, CanonicalRequiredGroup>();
    const group = eventGroups.get(groupRow.id) ?? { id: groupRow.id, memberIDs: [] };
    if (groupRow.inviteeId) group.memberIDs.push(groupRow.inviteeId);
    eventGroups.set(groupRow.id, group);
    groupsByEvent.set(groupRow.eventId, eventGroups);
  }

  return eventRows.map((event) => ({
    id: event.id,
    title: event.title,
    eventDate: event.eventDate,
    endDate: event.endDate,
    hostName: event.hostName,
    locationName: event.locationName,
    locationAddress: event.locationAddress,
    invitees: inviteesByEvent.get(event.id) ?? [],
    minimumParticipants: event.minimumParticipants,
    requiredGroups: [...(groupsByEvent.get(event.id)?.values() ?? [])],
    rsvpDeadline: event.rsvpDeadline,
    eventDescription: event.eventDescription,
    createdAt: event.createdAt,
    invitationsSent: Boolean(event.invitationsSent),
    privateResponsePolicy: policiesByEvent.get(event.id) ?? null,
    invitationDelivery: deliveriesByEvent.get(event.id) ?? null,
  }));
}

export async function getHostedEvents(
  db: D1Database,
  hostUserId: string,
): Promise<CanonicalEvent[]> {
  const result = await db
    .prepare(
      `${EVENT_SELECT}
       WHERE host_user_id = ?
       ORDER BY
         CASE WHEN event_date IS NULL THEN 1 ELSE 0 END,
         event_date ASC,
         created_at DESC
       LIMIT 100`,
    )
    .bind(hostUserId)
    .all<EventRow>();
  return hydrateEvents(db, result.results);
}

export async function deriveInviteToken(
  pepper: string,
  eventId: string,
  inviteeId: string,
  phoneHash: string,
): Promise<string> {
  return pepperedHash(
    pepper,
    "invite-token-material",
    `${eventId}:${inviteeId}:${phoneHash}`,
  );
}

export async function getEventsForUser(
  db: D1Database,
  bindings: Parameters<typeof getAuthConfig>[0],
  user: HerdUser,
) {
  const config = getAuthConfig(bindings);
  const phoneHash = await pepperedHash(config.pepper, "phone", user.phoneNumber);
  const accountKeyEpoch = await getActiveAccountKeyEpoch(db, user.id);
  if (!accountKeyEpoch) {
    throw new ApiError(
      500,
      "account_key_epoch_unavailable",
      "The account encryption key is unavailable.",
    );
  }
  const [hosted, invitedRows] = await Promise.all([
    getHostedEvents(db, user.id),
    db
      .prepare(
        `SELECT
           invitees.id AS inviteeId,
           invitees.event_id AS eventId,
           invitees.phone_hash AS phoneHash,
           invitees.token_ciphertext AS tokenCiphertext,
           invitees.token_nonce AS tokenNonce,
           invitees.token_storage_version AS tokenStorageVersion,
           response_envelopes.id AS responseEnvelopeId,
           response_envelopes.revision AS responseRevision
         FROM invitees
         JOIN events ON events.id = invitees.event_id
         LEFT JOIN response_envelopes
           ON response_envelopes.id = (
             SELECT latest.id
             FROM response_envelopes AS latest
             WHERE latest.invitee_id = invitees.id
             ORDER BY latest.revision DESC, latest.created_at DESC
             LIMIT 1
           )
         WHERE invitees.phone_hash = ?
           AND events.invitations_sent = 1
         ORDER BY events.event_date ASC
         LIMIT 100`,
      )
      .bind(phoneHash)
      .all<{
        inviteeId: string;
        eventId: string;
        phoneHash: string;
        tokenCiphertext: string | null;
        tokenNonce: string | null;
        tokenStorageVersion: number | null;
        responseEnvelopeId: string | null;
        responseRevision: number | null;
      }>(),
  ]);
  const hostedIds = new Set(hosted.map((event) => event.id));
  const invitedAccess = invitedRows.results.filter((row) => !hostedIds.has(row.eventId));
  let invitedEvents: CanonicalEvent[] = [];
  if (invitedAccess.length > 0) {
    const placeholders = invitedAccess.map(() => "?").join(", ");
    const rows = await db
      .prepare(`${EVENT_SELECT} WHERE id IN (${placeholders})`)
      .bind(...invitedAccess.map((row) => row.eventId))
      .all<EventRow>();
    invitedEvents = await hydrateEvents(db, rows.results);
  }
  const accessByEvent = new Map(invitedAccess.map((access) => [access.eventId, access]));
  const projected = [
    ...hosted.map((event) => ({
      ...event,
      role: "host" as const,
    })),
    ...(await Promise.all(
      invitedEvents.map(async (event) => {
        const access = accessByEvent.get(event.id)!;
        const publicEvent = toPublicEvent(event);
        return {
          ...publicEvent,
          invitees: publicEvent.invitees.map((invitee) => ({
            ...invitee,
            ...(invitee.id === access.inviteeId ? { isCurrentUser: true } : {}),
          })),
          role: "invitee" as const,
          inviteToken:
            config.testBypassEnabled &&
            event.id === "10000000-0000-4000-8000-000000000001"
              ? "poker-party"
              : access.tokenCiphertext
                ? await openSealedInviteToken(
                    config.pepper,
                    event.id,
                    access.inviteeId,
                    access,
                  )
                : await deriveInviteToken(
                    config.pepper,
                    event.id,
                    access.inviteeId,
                    access.phoneHash,
                  ),
          hasResponse: Boolean(access.responseEnvelopeId),
          responseRevision: access.responseRevision,
          accountKeyEpochId: accountKeyEpoch.id,
          accountKeyCommitment: accountKeyEpoch.keyCommitment,
        };
      }),
    )),
  ];
  return projected.sort((left, right) => {
    if (!left.eventDate && !right.eventDate) return left.createdAt.localeCompare(right.createdAt);
    if (!left.eventDate) return 1;
    if (!right.eventDate) return -1;
    return left.eventDate.localeCompare(right.eventDate);
  });
}

export async function getEventById(
  db: D1Database,
  eventId: string,
): Promise<(CanonicalEvent & { hostUserId: string }) | null> {
  const row = await db
    .prepare(`${EVENT_SELECT} WHERE id = ?`)
    .bind(eventId)
    .first<EventRow>();
  if (!row) return null;
  const [event] = await hydrateEvents(db, [row]);
  return { ...event, hostUserId: row.hostUserId };
}

export function toPublicEvent(event: CanonicalEvent): PublicEvent {
  const { invitationDelivery, ...publicEvent } = event;
  void invitationDelivery;
  return {
    ...publicEvent,
    invitees: event.invitees.map(({ id, displayName }) => ({ id, displayName })),
  };
}

export async function putHostedEvent(
  db: D1Database,
  bindings: Parameters<typeof getAuthConfig>[0],
  hostUser: Pick<HerdUser, "id" | "phoneNumber">,
  eventId: string,
  input: unknown,
): Promise<CanonicalEvent> {
  const event = validateCanonicalEvent(input, eventId);
  const hostUserId = hostUser.id;
  const existing = await db
    .prepare(
      `SELECT host_user_id AS hostUserId,
              invitations_sent AS invitationsSent,
              created_at AS createdAt
       FROM events WHERE id = ?`,
    )
    .bind(eventId)
    .first<{ hostUserId: string; invitationsSent: number | boolean; createdAt: string }>();
  if (existing && existing.hostUserId !== hostUserId) {
    throw new ApiError(404, "event_not_found", "The event was not found.");
  }
  const hostPhoneNumber = normalizePhoneNumber(hostUser.phoneNumber);
  if (event.invitees.some((invitee) => invitee.phoneNumber === hostPhoneNumber)) {
    throw new ApiError(
      400,
      "host_cannot_be_invited",
      "The host cannot also be invited to the same event.",
    );
  }

  const config = getAuthConfig(bindings);
  const nowIso = new Date().toISOString();
  const isSending = event.invitationsSent && !Boolean(existing?.invitationsSent);
  const existingPolicy = existing
    ? await getPrivateResponsePolicy(db, eventId)
    : null;
  if (existingPolicy) {
    if (!event.invitationsSent) {
      throw new ApiError(
        409,
        "event_policy_frozen",
        "Sent invitations and their privacy policy cannot be changed.",
      );
    }
    const candidate = await buildPrivateResponsePolicy(
      {
        ...event,
        createdAt: existing!.createdAt,
        privateResponsePolicy: null,
        invitationDelivery: null,
      },
      {
        ...config,
        privateResponse: {
          evaluatorKeyId: existingPolicy.evaluatorKeyId,
          evaluatorPublicKey: existingPolicy.evaluatorPublicKey,
          evaluatorMeasurement: existingPolicy.evaluatorMeasurement,
          releaseId: existingPolicy.releaseId,
        },
      },
      existingPolicy.frozenAt,
    );
    if (candidate.canonicalDocument !== existingPolicy.canonicalDocument) {
      throw new ApiError(
        409,
        "event_policy_frozen",
        "Sent invitations and their privacy policy cannot be changed.",
      );
    }
    await dispatchEventInvitations(db, bindings, eventId);
    const unchanged = await getEventById(db, eventId);
    if (!unchanged || unchanged.hostUserId !== hostUserId) {
      throw new ApiError(404, "event_not_found", "The event was not found.");
    }
    const { hostUserId: unchangedHostUserId, ...canonical } = unchanged;
    void unchangedHostUserId;
    return canonical;
  }
  if (existing && Boolean(existing.invitationsSent) && !event.invitationsSent) {
    throw new ApiError(
      409,
      "event_policy_frozen",
      "Sent invitations cannot be returned to draft status.",
    );
  }
  if (event.invitationsSent && event.rsvpDeadline! <= nowIso) {
    throw new ApiError(
      400,
      "invalid_event",
      "A sent event must have a future reply deadline.",
    );
  }
  if (isSending) assertInvitationDeliveryReady(bindings, event);

  if (event.invitees.length > 0) {
    const placeholders = event.invitees.map(() => "?").join(", ");
    const collisions = await db
      .prepare(
        `SELECT id, event_id AS eventId
         FROM invitees
         WHERE id IN (${placeholders}) AND event_id <> ?
         LIMIT 1`,
      )
      .bind(...event.invitees.map((invitee) => invitee.id), eventId)
      .first<{ id: string; eventId: string }>();
    if (collisions) {
      throw new ApiError(
        409,
        "invitee_id_conflict",
        "An invitee ID is already used by another event.",
      );
    }
  }

  const createdAt = existing ? null : event.createdAt ?? nowIso;
  const epochFence = event.invitationsSent
    ? await requireEvaluatorEpochPolicyFence(db, bindings, new Date(nowIso))
    : null;
  const policyToFreeze = event.invitationsSent
    ? await buildPrivateResponsePolicy(
        {
          ...event,
          createdAt: existing?.createdAt ?? createdAt ?? nowIso,
          privateResponsePolicy: null,
          invitationDelivery: null,
        },
        config,
        nowIso,
        bindings,
      )
    : null;
  const statements: D1PreparedStatement[] = [];
  if (existing) {
    statements.push(
      db
        .prepare(
          `UPDATE events SET
             title = ?,
             event_date = ?,
             end_date = ?,
             host_name = ?,
             location_name = ?,
             location_address = ?,
             minimum_participants = ?,
             rsvp_deadline = ?,
             event_description = ?,
             invitations_sent = ?,
             updated_at = ?
           WHERE id = ? AND host_user_id = ?
             AND NOT EXISTS (
               SELECT 1 FROM event_policies WHERE event_policies.event_id = events.id
             )`,
        )
        .bind(
          event.title,
          event.eventDate,
          event.endDate,
          event.hostName,
          event.locationName,
          event.locationAddress,
          event.minimumParticipants,
          event.rsvpDeadline,
          event.eventDescription,
          event.invitationsSent ? 1 : 0,
          nowIso,
          event.id,
          hostUserId,
        ),
    );
  } else {
    statements.push(
      db
        .prepare(
          `INSERT INTO events
            (id, host_user_id, title, event_date, end_date, host_name, location_name,
             location_address, minimum_participants, rsvp_deadline, event_description,
             invitations_sent, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          event.id,
          hostUserId,
          event.title,
          event.eventDate,
          event.endDate,
          event.hostName,
          event.locationName,
          event.locationAddress,
          event.minimumParticipants,
          event.rsvpDeadline,
          event.eventDescription,
          event.invitationsSent ? 1 : 0,
          createdAt,
          nowIso,
        ),
    );
  }
  statements.push(
    db
      .prepare(
        `DELETE FROM groups
         WHERE event_id = ?
           AND NOT EXISTS (
             SELECT 1 FROM event_policies WHERE event_policies.event_id = groups.event_id
           )`,
      )
      .bind(event.id),
  );
  if (event.invitees.length === 0) {
    statements.push(
      db
        .prepare(
          `DELETE FROM invitees
           WHERE event_id = ?
             AND NOT EXISTS (
               SELECT 1 FROM event_policies
               WHERE event_policies.event_id = invitees.event_id
             )`,
        )
        .bind(event.id),
    );
  } else {
    const placeholders = event.invitees.map(() => "?").join(", ");
    statements.push(
      db
        .prepare(
          `DELETE FROM invitees
           WHERE event_id = ? AND id NOT IN (${placeholders})
             AND NOT EXISTS (
               SELECT 1 FROM event_policies
               WHERE event_policies.event_id = invitees.event_id
             )`,
        )
        .bind(event.id, ...event.invitees.map((invitee) => invitee.id)),
    );
  }

  for (const invitee of event.invitees) {
    const phoneHash = await pepperedHash(config.pepper, "phone", invitee.phoneNumber);
    const inviteToken = await createSealedInviteToken(
      config.pepper,
      event.id,
      invitee.id,
    );
    statements.push(
      db
        .prepare(
          `INSERT INTO invitees
            (id, event_id, user_id, display_name, phone_number, phone_hash, token_hash,
             token_ciphertext, token_nonce, token_storage_version, created_at, updated_at)
           SELECT
             ?, ?,
             (SELECT id FROM users WHERE phone_hash = ? LIMIT 1),
             ?, ?, ?, ?, ?, ?, ?, ?, ?
           WHERE NOT EXISTS (
             SELECT 1 FROM event_policies WHERE event_policies.event_id = ?
           )
           ON CONFLICT(id) DO UPDATE SET
             user_id = excluded.user_id,
             display_name = excluded.display_name,
             phone_number = excluded.phone_number,
             phone_hash = excluded.phone_hash,
             token_hash = excluded.token_hash,
             token_ciphertext = excluded.token_ciphertext,
             token_nonce = excluded.token_nonce,
             token_storage_version = excluded.token_storage_version,
             updated_at = excluded.updated_at
           WHERE invitees.event_id = excluded.event_id
             AND NOT EXISTS (
               SELECT 1 FROM event_policies
               WHERE event_policies.event_id = invitees.event_id
             )`,
        )
        .bind(
          invitee.id,
          event.id,
          phoneHash,
          invitee.displayName,
          invitee.phoneNumber,
          phoneHash,
          inviteToken.tokenHash,
          inviteToken.tokenCiphertext,
          inviteToken.tokenNonce,
          inviteToken.tokenStorageVersion,
          nowIso,
          nowIso,
          event.id,
        ),
    );
  }
  if (isSending) {
    statements.push(
      ...prepareInvitationDeliveryStatements(db, bindings, event, nowIso),
    );
  }
  event.requiredGroups.forEach((group, groupPosition) => {
    statements.push(
      db
        .prepare(
          `INSERT INTO groups (id, event_id, position)
           SELECT ?, ?, ?
           WHERE NOT EXISTS (
             SELECT 1 FROM event_policies WHERE event_policies.event_id = ?
           )`,
        )
        .bind(group.id, event.id, groupPosition, event.id),
    );
    group.memberIDs.forEach((inviteeId, memberPosition) => {
      statements.push(
        db
          .prepare(
            `INSERT INTO group_members (group_id, invitee_id, position)
             SELECT ?, ?, ?
             WHERE EXISTS (
               SELECT 1 FROM groups
               WHERE groups.id = ?
                 AND NOT EXISTS (
                   SELECT 1 FROM event_policies
                   WHERE event_policies.event_id = groups.event_id
                 )
             )`,
          )
          .bind(group.id, inviteeId, memberPosition, group.id),
      );
    });
  });
  if (policyToFreeze) {
    statements.push(
      prepareInsertPrivateResponsePolicy(db, event.id, policyToFreeze, epochFence!),
      prepareInsertPendingEventResolution(
        db,
        event.id,
        policyToFreeze.policyHash,
        policyToFreeze.frozenAt,
      ),
    );
  }
  try {
    await db.batch(statements);
  } catch (error) {
    const raced = await getEventById(db, event.id);
    if (raced?.hostUserId === hostUserId && raced.privateResponsePolicy) {
      if (
        policyToFreeze &&
        raced.privateResponsePolicy.canonicalDocument === policyToFreeze.canonicalDocument
      ) {
        await dispatchEventInvitations(db, bindings, event.id);
        const recovered = await getEventById(db, event.id);
        if (!recovered || recovered.hostUserId !== hostUserId) {
          throw new ApiError(404, "event_not_found", "The event was not found.");
        }
        const { hostUserId: racedHostUserId, ...canonical } = recovered;
        void racedHostUserId;
        return canonical;
      }
      throw new ApiError(
        409,
        "event_policy_frozen",
        "Sent invitations and their privacy policy cannot be changed.",
      );
    }
    throw error;
  }

  if (isSending) {
    await dispatchEventInvitations(db, bindings, event.id);
  }
  const saved = await getEventById(db, event.id);
  if (!saved || saved.hostUserId !== hostUserId) {
    throw new ApiError(500, "event_save_failed", "The event could not be saved.");
  }
  if (
    (saved.privateResponsePolicy && !event.invitationsSent) ||
    (policyToFreeze &&
      saved.privateResponsePolicy?.canonicalDocument !== policyToFreeze.canonicalDocument)
  ) {
    throw new ApiError(
      409,
      "event_policy_frozen",
      "Sent invitations and their privacy policy cannot be changed.",
    );
  }
  const { hostUserId: savedHostUserId, ...canonical } = saved;
  void savedHostUserId;
  return canonical;
}

export async function deleteHostedEvent(
  db: D1Database,
  hostUserId: string,
  eventId: string,
): Promise<void> {
  const result = await db
    .prepare("DELETE FROM events WHERE id = ? AND host_user_id = ?")
    .bind(eventId, hostUserId)
    .run();
  if ((result.meta.changes ?? 0) === 0) {
    throw new ApiError(404, "event_not_found", "The event was not found.");
  }
}
