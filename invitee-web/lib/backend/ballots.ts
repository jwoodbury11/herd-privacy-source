import type { HerdBindings } from "@/db";

import { getAuthenticatedSession } from "./auth";
import { deriveBallotId, deriveBallotMemberId } from "./ballot-identifiers";
import { getAuthConfig } from "./config";
import { pepperedHash } from "./crypto";
import { getEventById } from "./events";
import { ApiError, requireString } from "./http";

const BALLOT_PROTOCOL_VERSION = 2;
const BALLOT_KEY_VERSION = 1;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

type BallotAccess = {
  eventId: string;
  inviteeId: string;
  phoneHash: string;
  hostUserId: string;
};

export type SimplifiedBallotDraft = {
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: Array<{ id: string; memberIDs: string[] }>;
};

export type StoredSimplifiedBallot = SimplifiedBallotDraft & {
  protocolVersion: 2;
  ballotId: string;
  revision: number;
  createdAt: string;
};

type BallotRow = {
  ballotId: string;
  revision: number;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: string;
  contentDigest: string;
  createdAt: string;
};

async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/gu, "");
}

async function requireAccess(
  request: Request,
  db: D1Database,
  bindings: HerdBindings,
  rawToken: string,
) {
  const token = requireString(rawToken, "invite token", { min: 8, max: 200 });
  if (!/^[A-Za-z0-9_-]+$/u.test(token)) {
    throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  }
  const config = getAuthConfig(bindings);
  const tokenHash = await pepperedHash(config.pepper, "invite-token", token);
  const access = await db
    .prepare(
      `SELECT invitees.event_id AS eventId,
              invitees.id AS inviteeId,
              invitees.phone_hash AS phoneHash,
              events.host_user_id AS hostUserId
       FROM invitees
       JOIN events ON events.id = invitees.event_id
       WHERE invitees.token_hash = ?`,
    )
    .bind(tokenHash)
    .first<BallotAccess>();
  if (!access) throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  const session = await getAuthenticatedSession(request, { db, bindings });
  const sessionPhoneHash = await pepperedHash(config.pepper, "phone", session!.user.phoneNumber);
  if (sessionPhoneHash !== access.phoneHash || session!.user.id === access.hostUserId) {
    throw new ApiError(403, "invite_for_different_account", "This invitation belongs to a different account.");
  }
  const event = await getEventById(db, access.eventId);
  if (!event) throw new ApiError(404, "invite_not_found", "The invitation was not found.");
  return { access, event };
}

async function memberMaps(
  bindings: HerdBindings,
  eventId: string,
  invitees: Array<{ id: string }>,
) {
  const entries = await Promise.all(invitees.map(async ({ id }) => [
    id,
    await deriveBallotMemberId(bindings, eventId, id),
  ] as const));
  return {
    toBallot: new Map(entries),
    fromBallot: new Map(entries.map(([id, ballotMemberId]) => [ballotMemberId, id])),
  };
}

function validateDraft(
  value: Record<string, unknown>,
  participantCount: number,
  allowedMemberIds: Set<string>,
  currentInviteeId: string,
): SimplifiedBallotDraft {
  const response = value.response;
  if (response !== "going" && response !== "cant_commit") {
    throw new ApiError(400, "invalid_ballot", "Choose a valid private reply.");
  }
  const minimumParticipants = value.minimumParticipants;
  if (
    response === "going"
      ? !Number.isInteger(minimumParticipants)
        || (minimumParticipants as number) < 2
        || (minimumParticipants as number) > participantCount
      : minimumParticipants !== null
  ) {
    throw new ApiError(400, "invalid_ballot", "The minimum attendee condition is invalid.");
  }
  if (!Array.isArray(value.requiredGroups) || value.requiredGroups.length > participantCount - 1) {
    throw new ApiError(400, "invalid_ballot", "The attendee conditions are invalid.");
  }
  const seenMembers = new Set<string>();
  const seenGroups = new Set<string>();
  const requiredGroups = value.requiredGroups.map((unknownGroup) => {
    if (!unknownGroup || typeof unknownGroup !== "object" || Array.isArray(unknownGroup)) {
      throw new ApiError(400, "invalid_ballot", "An attendee condition is invalid.");
    }
    const group = unknownGroup as Record<string, unknown>;
    const id = requireString(group.id, "condition ID", { min: 1, max: 120 });
    if (seenGroups.has(id) || !Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      throw new ApiError(400, "invalid_ballot", "An attendee condition is invalid.");
    }
    seenGroups.add(id);
    const memberIDs = group.memberIDs.map((unknownMember) => {
      const memberID = requireString(unknownMember, "attendee ID", { min: 36, max: 36 }).toLowerCase();
      if (
        !UUID_PATTERN.test(memberID)
        || memberID === currentInviteeId
        || !allowedMemberIds.has(memberID)
        || seenMembers.has(memberID)
      ) {
        throw new ApiError(400, "invalid_ballot", "An attendee condition contains an invalid person.");
      }
      seenMembers.add(memberID);
      return memberID;
    });
    return { id, memberIDs };
  });
  if (response === "cant_commit" && requiredGroups.length > 0) {
    throw new ApiError(400, "invalid_ballot", "A can’t-commit reply cannot include conditions.");
  }
  return {
    response,
    minimumParticipants: minimumParticipants as number | null,
    requiredGroups,
  };
}

async function latestBallot(db: D1Database, ballotId: string): Promise<BallotRow | null> {
  return db
    .prepare(
      `SELECT ballot_id AS ballotId, revision, response,
              minimum_participants AS minimumParticipants,
              required_groups AS requiredGroups,
              content_digest AS contentDigest,
              created_at AS createdAt
       FROM ballot_revisions
       WHERE ballot_id = ?
       ORDER BY revision DESC
       LIMIT 1`,
    )
    .bind(ballotId)
    .first<BallotRow>();
}

export async function getOwnBallot(
  request: Request,
  db: D1Database,
  bindings: HerdBindings,
  rawToken: string,
): Promise<StoredSimplifiedBallot | null> {
  const { access, event } = await requireAccess(request, db, bindings, rawToken);
  const ballotId = await deriveBallotId(bindings, access.eventId, access.inviteeId);
  const row = await latestBallot(db, ballotId);
  if (!row) return null;
  const { fromBallot } = await memberMaps(bindings, access.eventId, event.invitees);
  const storedGroups = JSON.parse(row.requiredGroups) as Array<{ id: string; memberIDs: string[] }>;
  return {
    protocolVersion: 2,
    ballotId,
    revision: row.revision,
    response: row.response,
    minimumParticipants: row.minimumParticipants,
    requiredGroups: storedGroups.map((group) => ({
      id: group.id,
      memberIDs: group.memberIDs.map((memberID) => {
        const inviteeId = fromBallot.get(memberID);
        if (!inviteeId) throw new ApiError(500, "invalid_ballot", "The saved private reply is invalid.");
        return inviteeId;
      }),
    })),
    createdAt: row.createdAt,
  };
}

export async function putOwnBallot(
  request: Request,
  db: D1Database,
  bindings: HerdBindings,
  rawToken: string,
  payload: Record<string, unknown>,
): Promise<StoredSimplifiedBallot> {
  const { access, event } = await requireAccess(request, db, bindings, rawToken);
  const resolution = await db
    .prepare("SELECT status FROM event_resolutions WHERE event_id = ?")
    .bind(access.eventId)
    .first<{ status: string }>();
  if (resolution?.status === "confirmed") {
    throw new ApiError(409, "event_already_confirmed", "Confirmed events can’t accept reply changes.");
  }
  if (event.rsvpDeadline && event.rsvpDeadline <= new Date().toISOString()) {
    throw new ApiError(409, "rsvp_closed", "Replies are closed for this event.");
  }
  const allowedMemberIds = new Set(event.invitees.map(({ id }) => id));
  const draft = validateDraft(
    payload,
    event.invitees.length + 1,
    allowedMemberIds,
    access.inviteeId,
  );
  const ballotId = await deriveBallotId(bindings, access.eventId, access.inviteeId);
  const { toBallot } = await memberMaps(bindings, access.eventId, event.invitees);
  const storedGroups = draft.requiredGroups.map((group) => ({
    id: group.id,
    memberIDs: group.memberIDs.map((memberID) => toBallot.get(memberID)!),
  }));
  const current = await latestBallot(db, ballotId);
  if (
    current &&
    current.response === draft.response &&
    current.minimumParticipants === draft.minimumParticipants &&
    current.requiredGroups === JSON.stringify(storedGroups)
  ) {
    return {
      protocolVersion: 2,
      ballotId,
      revision: current.revision,
      response: draft.response,
      minimumParticipants: draft.minimumParticipants,
      requiredGroups: draft.requiredGroups,
      createdAt: current.createdAt,
    };
  }
  const revision = (current?.revision ?? 0) + 1;
  const createdAt = new Date().toISOString();
  const canonicalContent = JSON.stringify({
    protocolVersion: BALLOT_PROTOCOL_VERSION,
    keyVersion: BALLOT_KEY_VERSION,
    eventId: access.eventId,
    ballotId,
    revision,
    response: draft.response,
    minimumParticipants: draft.minimumParticipants,
    requiredGroups: storedGroups,
  });
  const contentDigest = await digest(canonicalContent);
  await db
    .prepare(
      `INSERT INTO ballot_revisions (
         ballot_id, revision, protocol_version, key_version, event_id,
         response, minimum_participants, required_groups, source,
         correction_reason, content_digest, created_at
       ) VALUES (?, ?, 2, 1, ?, ?, ?, ?, 'user', NULL, ?, ?)`,
    )
    .bind(
      ballotId,
      revision,
      access.eventId,
      draft.response,
      draft.minimumParticipants,
      JSON.stringify(storedGroups),
      contentDigest,
      createdAt,
    )
    .run();
  return {
    protocolVersion: 2,
    ballotId,
    revision,
    response: draft.response,
    minimumParticipants: draft.minimumParticipants,
    requiredGroups: draft.requiredGroups,
    createdAt,
  };
}
