import { getActiveAccountKeyEpoch } from "./account-keys";
import { deriveBallotId } from "./ballot-identifiers";
import { getAuthConfig } from "./config";
import { pepperedHash } from "./crypto";
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
  DEFAULT_EVENT_IMAGE_ID,
  EVENT_IMAGE_IDS,
  type EventImageID,
} from "@/lib/event-images";
import {
  getPrivateResponsePolicies,
} from "./policy";
import type {
  CanonicalEvent,
  CanonicalInvitee,
  CanonicalRequiredGroup,
  EventResolution,
  HerdUser,
  PublicEvent,
} from "./types";

export type InviteeResponseHistory = {
  missedConfirmedEvents: number;
  totalConfirmedEvents: number;
};

export async function getRespondedInviteeIdsByEvent(
  db: D1Database,
  bindings: Parameters<typeof getAuthConfig>[0],
  eventIds: string[],
): Promise<Map<string, Set<string>>> {
  const respondedByEvent = new Map<string, Set<string>>();
  const uniqueEventIds = [...new Set(eventIds)];
  for (let offset = 0; offset < uniqueEventIds.length; offset += 80) {
    const chunk = uniqueEventIds.slice(offset, offset + 80);
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => "?").join(", ");
    const rows = await db
      .prepare(
        `SELECT DISTINCT
           invitees.event_id AS eventId,
           response_envelopes.invitee_id AS inviteeId
         FROM response_envelopes
         JOIN invitees ON invitees.id = response_envelopes.invitee_id
         WHERE invitees.event_id IN (${placeholders})`,
      )
      .bind(...chunk)
      .all<{ eventId: string; inviteeId: string }>();
    for (const row of rows.results) {
      const responded = respondedByEvent.get(row.eventId) ?? new Set<string>();
      responded.add(row.inviteeId);
      respondedByEvent.set(row.eventId, responded);
    }

    const [ballotRows, inviteeRows] = await Promise.all([
      db
        .prepare(
          `SELECT DISTINCT event_id AS eventId, ballot_id AS ballotId
           FROM ballot_revisions
           WHERE event_id IN (${placeholders})`,
        )
        .bind(...chunk)
        .all<{ eventId: string; ballotId: string }>(),
      db
        .prepare(
          `SELECT event_id AS eventId, id AS inviteeId
           FROM invitees
           WHERE event_id IN (${placeholders})`,
        )
        .bind(...chunk)
        .all<{ eventId: string; inviteeId: string }>(),
    ]);
    const storedBallots = new Set(
      ballotRows.results.map(({ eventId, ballotId }) => `${eventId}:${ballotId}`),
    );
    for (const invitee of inviteeRows.results) {
      const ballotId = await deriveBallotId(bindings, invitee.eventId, invitee.inviteeId);
      if (!storedBallots.has(`${invitee.eventId}:${ballotId}`)) continue;
      const responded = respondedByEvent.get(invitee.eventId) ?? new Set<string>();
      responded.add(invitee.inviteeId);
      respondedByEvent.set(invitee.eventId, responded);
    }
  }
  return respondedByEvent;
}

type EventRow = {
  id: string;
  hostUserId: string;
  title: string;
  eventDate: string | null;
  eventTimeZone: string | null;
  endDate: string | null;
  hostName: string;
  locationName: string;
  locationAddress: string;
  minimumParticipants: number;
  allowsAttendeesToAddGuests: number | boolean;
  rsvpDeadline: string | null;
  eventDescription: string;
  eventImageID: EventImageID;
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
  event_time_zone AS eventTimeZone,
  end_date AS endDate,
  host_name AS hostName,
  location_name AS locationName,
  location_address AS locationAddress,
  minimum_participants AS minimumParticipants,
  allows_attendees_to_add_guests AS allowsAttendeesToAddGuests,
  rsvp_deadline AS rsvpDeadline,
  event_description AS eventDescription,
  event_image_id AS eventImageID,
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

function normalizeTimeZone(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const candidate = requireString(value, "event.eventTimeZone", { max: 100 });
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: candidate }).format();
  } catch {
    throw new ApiError(400, "invalid_event", "event.eventTimeZone must be a valid IANA time zone.");
  }
  return candidate;
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
  const eventImageID = input.eventImageID ?? DEFAULT_EVENT_IMAGE_ID;
  if (
    typeof eventImageID !== "string" ||
    !EVENT_IMAGE_IDS.includes(eventImageID as EventImageID)
  ) {
    throw new ApiError(400, "invalid_event", "event.eventImageID is not supported.");
  }
  const eventDate = normalizeIsoDate(input.eventDate, "event.eventDate", {
    nullable: true,
  });
  const eventTimeZone = normalizeTimeZone(input.eventTimeZone);
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
  const allowsAttendeesToAddGuests = input.allowsAttendeesToAddGuests ?? true;
  if (typeof allowsAttendeesToAddGuests !== "boolean") {
    throw new ApiError(
      400,
      "invalid_event",
      "event.allowsAttendeesToAddGuests must be boolean.",
    );
  }
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
    eventTimeZone,
    endDate,
    hostName,
    locationName,
    locationAddress,
    invitees,
    minimumParticipants,
    allowsAttendeesToAddGuests,
    requiredGroups,
    rsvpDeadline,
    eventDescription,
    eventImageID: eventImageID as EventImageID,
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
    eventTimeZone: event.eventTimeZone,
    endDate: event.endDate,
    hostName: event.hostName,
    locationName: event.locationName,
    locationAddress: event.locationAddress,
    invitees: inviteesByEvent.get(event.id) ?? [],
    minimumParticipants: event.minimumParticipants,
    allowsAttendeesToAddGuests: Boolean(event.allowsAttendeesToAddGuests),
    requiredGroups: [...(groupsByEvent.get(event.id)?.values() ?? [])],
    rsvpDeadline: event.rsvpDeadline,
    eventDescription: event.eventDescription,
    eventImageID: event.eventImageID ?? DEFAULT_EVENT_IMAGE_ID,
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
           response_envelopes.revision AS responseRevision,
           response_transparency_entries.receipt_signature AS responseReceiptSignature,
           response_transparency_entries.signed_at AS responseSignedAt,
           response_transparency_heads.signature AS responseHeadSignature,
           response_transparency_heads.generated_at AS responseHeadGeneratedAt
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
         LEFT JOIN response_transparency_entries
           ON response_transparency_entries.envelope_id = response_envelopes.id
         LEFT JOIN response_transparency_heads
           ON response_transparency_heads.log_index = response_transparency_entries.log_index
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
        responseReceiptSignature: string | null;
        responseSignedAt: string | null;
        responseHeadSignature: string | null;
        responseHeadGeneratedAt: string | null;
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
  const respondedByEvent = await getRespondedInviteeIdsByEvent(
    db,
    bindings,
    [...hosted.map((event) => event.id), ...invitedEvents.map((event) => event.id)],
  );
  const projected = [
    ...hosted.map((event) => ({
      ...event,
      invitees: event.invitees.map((invitee) => ({
        ...invitee,
        hasResponded: respondedByEvent.get(event.id)?.has(invitee.id) ?? false,
      })),
      role: "host" as const,
    })),
    ...(await Promise.all(
      invitedEvents.map(async (event) => {
        const access = accessByEvent.get(event.id)!;
        const publicEvent = toPublicEvent(event);
        const hasBallot = respondedByEvent.get(event.id)?.has(access.inviteeId) ?? false;
        const ballotRevisionRow = hasBallot
          ? await db
              .prepare(
                `SELECT MAX(revision) AS revision
                 FROM ballot_revisions WHERE ballot_id = ?`,
              )
              .bind(await deriveBallotId(bindings, event.id, access.inviteeId))
              .first<{ revision: number | null }>()
          : null;
        const canViewResponseProgress = Boolean(access.responseEnvelopeId) || hasBallot;
        return {
          ...publicEvent,
          invitees: publicEvent.invitees.map((invitee) => ({
            ...invitee,
            ...(invitee.id === access.inviteeId ? { isCurrentUser: true } : {}),
            ...(canViewResponseProgress
              ? {
                  hasResponded:
                    respondedByEvent.get(event.id)?.has(invitee.id) ?? false,
                }
              : {}),
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
          hasBallot,
          responseRevision: access.responseRevision ?? ballotRevisionRow?.revision ?? null,
          responseCertificationStatus: access.responseEnvelopeId
            ? access.responseReceiptSignature &&
                access.responseSignedAt &&
                access.responseHeadSignature &&
                access.responseHeadGeneratedAt
              ? ("certified" as const)
              : ("pending" as const)
            : null,
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

export async function getInviteeResponseHistories(
  db: D1Database,
  events: Array<{
    id: string;
    invitees: Array<{ id: string; isCurrentUser?: boolean }>;
    resolution?: EventResolution | null;
  }>,
  nowIso = new Date().toISOString(),
): Promise<Map<string, InviteeResponseHistory>> {
  const invitees = events.flatMap((event) =>
    event.invitees.map((invitee) => ({ eventId: event.id, invitee })),
  ).filter(({ eventId, invitee }) =>
    events.some((event) =>
      event.id === eventId
        && event.resolution?.status === "confirmed"
        && event.resolution.attendanceRevealed,
    ) || invitee.isCurrentUser,
  );
  const phoneHashByInviteeId = new Map<string, string>();
  const uniqueInviteeIds = [...new Set(invitees.map(({ invitee }) => invitee.id))];
  for (let offset = 0; offset < uniqueInviteeIds.length; offset += 100) {
    const chunk = uniqueInviteeIds.slice(offset, offset + 100);
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => "?").join(", ");
    const rows = await db
      .prepare(
        `SELECT id, phone_hash AS phoneHash
         FROM invitees
         WHERE id IN (${placeholders})`,
      )
      .bind(...chunk)
      .all<{ id: string; phoneHash: string }>();
    for (const row of rows.results) phoneHashByInviteeId.set(row.id, row.phoneHash);
  }
  const phoneEntries = invitees.flatMap(({ eventId, invitee }) => {
    const phoneHash = phoneHashByInviteeId.get(invitee.id);
    return phoneHash ? [{ key: `${eventId}:${invitee.id}`, phoneHash }] : [];
  });
  const uniquePhoneHashes = [...new Set(phoneEntries.map(({ phoneHash }) => phoneHash))];
  const historiesByPhoneHash = new Map<string, InviteeResponseHistory>();

  for (let offset = 0; offset < uniquePhoneHashes.length; offset += 100) {
    const chunk = uniquePhoneHashes.slice(offset, offset + 100);
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => "?").join(", ");
    const rows = await db
      .prepare(
        `SELECT invitees.phone_hash AS phoneHash,
                COUNT(*) AS totalConfirmedEvents,
                SUM(
                  CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM response_envelopes
                    WHERE response_envelopes.invitee_id = invitees.id
                  ) THEN 1 ELSE 0 END
                ) AS missedConfirmedEvents
         FROM invitees
         JOIN events ON events.id = invitees.event_id
         JOIN event_resolutions ON event_resolutions.event_id = invitees.event_id
         WHERE invitees.phone_hash IN (${placeholders})
           AND event_resolutions.status = 'confirmed'
           AND events.rsvp_deadline IS NOT NULL
           AND events.rsvp_deadline <= ?
         GROUP BY invitees.phone_hash`,
      )
      .bind(...chunk, nowIso)
      .all<{
        phoneHash: string;
        missedConfirmedEvents: number;
        totalConfirmedEvents: number;
      }>();
    for (const row of rows.results) {
      historiesByPhoneHash.set(row.phoneHash, {
        missedConfirmedEvents: Number(row.missedConfirmedEvents),
        totalConfirmedEvents: Number(row.totalConfirmedEvents),
      });
    }
  }

  return new Map(phoneEntries.map(({ key, phoneHash }) => [
    key,
    historiesByPhoneHash.get(phoneHash) ?? {
      missedConfirmedEvents: 0,
      totalConfirmedEvents: 0,
    },
  ]));
}

export function toPublicEvent(
  event: CanonicalEvent,
): PublicEvent {
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
  if (existing && Boolean(existing.invitationsSent) && !event.invitationsSent) {
    throw new ApiError(
      409,
      "event_already_sent",
      "Sent invitations cannot be returned to draft status.",
    );
  }
  if (isSending) assertInvitationDeliveryReady(bindings, event);
  let isConfirmed = false;
  if (existing) {
    const resolution = await db
      .prepare("SELECT status FROM event_resolutions WHERE event_id = ?")
      .bind(eventId)
      .first<{ status: string }>();
    isConfirmed = resolution?.status === "confirmed";
    if (isConfirmed) {
      const stored = await getEventById(db, eventId);
      if (!stored || stored.hostUserId !== hostUserId) {
        throw new ApiError(404, "event_not_found", "The event was not found.");
      }
      const attendanceSettingsChanged =
        event.minimumParticipants !== stored.minimumParticipants ||
        event.rsvpDeadline !== stored.rsvpDeadline ||
        event.allowsAttendeesToAddGuests !== stored.allowsAttendeesToAddGuests ||
        JSON.stringify(event.invitees) !== JSON.stringify(stored.invitees) ||
        JSON.stringify(event.requiredGroups) !== JSON.stringify(stored.requiredGroups);
      if (attendanceSettingsChanged) {
        throw new ApiError(
          409,
          "confirmed_event_attendance_locked",
          "Attendance settings and the RSVP deadline can’t be changed after confirmation.",
        );
      }
    }
  }
  if (!isConfirmed && event.invitationsSent && event.rsvpDeadline! <= nowIso) {
    throw new ApiError(
      400,
      "invalid_event",
      "A sent event must have a future reply deadline.",
    );
  }

  if (isConfirmed && !event.invitationsSent) {
    throw new ApiError(
      409,
      "event_already_confirmed",
      "A confirmed event can’t return to draft status.",
    );
  }

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
  const statements: D1PreparedStatement[] = [];
  if (existing) {
    if (!isConfirmed) {
      statements.push(
        // Protocol-v2 ballots are independent of the old frozen evaluator
        // policy. Converting a legacy event removes only that obsolete policy
        // and its cached result; it never deletes a private ballot.
        db.prepare("DELETE FROM event_resolutions WHERE event_id = ?").bind(event.id),
        db.prepare("DELETE FROM event_policies WHERE event_id = ?").bind(event.id),
      );
    }
    statements.push(
      db
        .prepare(
          `UPDATE events SET
             title = ?,
             event_date = ?,
             event_time_zone = ?,
             end_date = ?,
             host_name = ?,
             location_name = ?,
             location_address = ?,
             minimum_participants = ?,
             allows_attendees_to_add_guests = ?,
             rsvp_deadline = ?,
             event_description = ?,
             event_image_id = ?,
             invitations_sent = ?,
             updated_at = ?
           WHERE id = ? AND host_user_id = ?
             ${isConfirmed ? "" : `AND NOT EXISTS (
               SELECT 1 FROM event_policies WHERE event_policies.event_id = events.id
             )`}`,
        )
        .bind(
          event.title,
          event.eventDate,
          event.eventTimeZone,
          event.endDate,
          event.hostName,
          event.locationName,
          event.locationAddress,
          event.minimumParticipants,
          event.allowsAttendeesToAddGuests ? 1 : 0,
          event.rsvpDeadline,
          event.eventDescription,
          event.eventImageID,
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
            (id, host_user_id, title, event_date, event_time_zone, end_date, host_name, location_name,
             location_address, minimum_participants, allows_attendees_to_add_guests,
             rsvp_deadline, event_description, event_image_id,
             invitations_sent, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          event.id,
          hostUserId,
          event.title,
          event.eventDate,
          event.eventTimeZone,
          event.endDate,
          event.hostName,
          event.locationName,
          event.locationAddress,
          event.minimumParticipants,
          event.allowsAttendeesToAddGuests ? 1 : 0,
          event.rsvpDeadline,
          event.eventDescription,
          event.eventImageID,
          event.invitationsSent ? 1 : 0,
          createdAt,
          nowIso,
        ),
    );
  }
  if (!isConfirmed) {
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
  }
  await db.batch(statements);

  if (isSending) {
    await dispatchEventInvitations(db, bindings, event.id);
  }
  const saved = await getEventById(db, event.id);
  if (!saved || saved.hostUserId !== hostUserId) {
    throw new ApiError(500, "event_save_failed", "The event could not be saved.");
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

export async function addEventAttendees(
  db: D1Database,
  bindings: Parameters<typeof getAuthConfig>[0],
  user: Pick<HerdUser, "id" | "phoneNumber">,
  eventId: string,
  input: unknown,
): Promise<void> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new ApiError(400, "invalid_attendees", "The attendee request must be an object.");
  }
  const additions = (input as Record<string, unknown>).invitees;
  if (!Array.isArray(additions) || additions.length === 0) {
    throw new ApiError(400, "invalid_attendees", "Choose at least one attendee to add.");
  }

  const stored = await getEventById(db, eventId);
  if (!stored) throw new ApiError(404, "event_not_found", "The event was not found.");

  const config = getAuthConfig(bindings);
  const callerPhoneHash = await pepperedHash(config.pepper, "phone", user.phoneNumber);
  const isHost = stored.hostUserId === user.id;
  const isAttendee = isHost
    ? false
    : Boolean(await db
        .prepare("SELECT 1 AS found FROM invitees WHERE event_id = ? AND phone_hash = ?")
        .bind(eventId, callerPhoneHash)
        .first<{ found: number }>());
  if (!isHost && !isAttendee) {
    throw new ApiError(404, "event_not_found", "The event was not found.");
  }
  if (!isHost && !stored.allowsAttendeesToAddGuests) {
    throw new ApiError(
      403,
      "attendee_additions_disabled",
      "The host isn’t allowing attendees to add guests for this event.",
    );
  }

  const { hostUserId, privateResponsePolicy, invitationDelivery, ...editable } = stored;
  void hostUserId;
  void privateResponsePolicy;
  void invitationDelivery;
  const candidate = validateCanonicalEvent(
    { ...editable, invitees: [...stored.invitees, ...additions] },
    eventId,
  );
  const newInviteeIds = new Set(
    candidate.invitees.slice(stored.invitees.length).map((invitee) => invitee.id),
  );
  const newInvitees = candidate.invitees.filter((invitee) => newInviteeIds.has(invitee.id));
  const hostPhoneNumber = normalizePhoneNumber(user.phoneNumber);
  const actualHostPhone = isHost
    ? hostPhoneNumber
    : normalizePhoneNumber((await db
        .prepare(
          `SELECT users.phone_number AS phoneNumber
           FROM events JOIN users ON users.id = events.host_user_id
           WHERE events.id = ?`,
        )
        .bind(eventId)
        .first<{ phoneNumber: string }>())!.phoneNumber);
  if (newInvitees.some((invitee) => invitee.phoneNumber === actualHostPhone)) {
    throw new ApiError(
      400,
      "host_cannot_be_invited",
      "The host cannot also be invited to the same event.",
    );
  }

  if (!stored.invitationsSent) {
    if (!isHost) {
      throw new ApiError(403, "event_not_sent", "Only the host can change a draft event.");
    }
    await putHostedEvent(db, bindings, user, eventId, candidate);
    return;
  }

  const nowIso = new Date().toISOString();
  const resolution = await db
    .prepare("SELECT status FROM event_resolutions WHERE event_id = ?")
    .bind(eventId)
    .first<{ status: string }>();
  if (resolution?.status === "confirmed") {
    throw new ApiError(
      409,
      "event_already_confirmed",
      "Attendees can’t be added after an event is confirmed.",
    );
  }
  if (!stored.rsvpDeadline || stored.rsvpDeadline <= nowIso) {
    throw new ApiError(409, "rsvp_closed", "Attendees can’t be added after replies close.");
  }
  assertInvitationDeliveryReady(bindings, { invitees: newInvitees });

  if (newInvitees.length > 0) {
    const placeholders = newInvitees.map(() => "?").join(", ");
    const collision = await db
      .prepare(
        `SELECT id FROM invitees
         WHERE id IN (${placeholders}) AND event_id <> ?
         LIMIT 1`,
      )
      .bind(...newInvitees.map((invitee) => invitee.id), eventId)
      .first<{ id: string }>();
    if (collision) {
      throw new ApiError(
        409,
        "invitee_id_conflict",
        "An attendee ID is already used by another event.",
      );
    }
  }

  const nextEvent: CanonicalEvent = {
    ...stored,
    invitees: candidate.invitees,
    allowsAttendeesToAddGuests: candidate.allowsAttendeesToAddGuests,
    privateResponsePolicy: null,
    invitationDelivery: null,
  };
  const statements: D1PreparedStatement[] = [];
  for (const invitee of newInvitees) {
    const phoneHash = await pepperedHash(config.pepper, "phone", invitee.phoneNumber);
    const inviteToken = await createSealedInviteToken(config.pepper, eventId, invitee.id);
    statements.push(
      db.prepare(
        `INSERT INTO invitees
          (id, event_id, user_id, display_name, phone_number, phone_hash, token_hash,
           token_ciphertext, token_nonce, token_storage_version, created_at, updated_at)
         VALUES (
           ?, ?, (SELECT id FROM users WHERE phone_hash = ? LIMIT 1),
           ?, ?, ?, ?, ?, ?, ?, ?, ?
         )`,
      ).bind(
        invitee.id,
        eventId,
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
      ),
    );
  }
  statements.push(
    // A roster edit invalidates only the cached result and the obsolete v1
    // frozen policy. Protocol-v2 ballot revisions are intentionally retained.
    db.prepare("DELETE FROM event_resolutions WHERE event_id = ?").bind(eventId),
    db.prepare("DELETE FROM event_policies WHERE event_id = ?").bind(eventId),
    db.prepare("UPDATE events SET updated_at = ? WHERE id = ?").bind(nowIso, eventId),
    ...prepareInvitationDeliveryStatements(db, bindings, nextEvent, nowIso),
  );
  await db.batch(statements);
  await dispatchEventInvitations(db, bindings, eventId);
}
