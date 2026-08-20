import type { HerdBindings } from "@/db";

import { deriveBallotId, deriveBallotMemberId } from "./ballot-identifiers";
import { sendResolutionTransitionNotifications } from "./resolution-notifications";
import type { EventResolution } from "./types";

type ResolutionEvent = {
  id: string;
  title?: string;
  eventDate?: string | null;
  invitationsSent: boolean;
  minimumParticipants: number;
  requiredGroups: Array<{ memberIDs: string[] }>;
  rsvpDeadline: string | null;
  invitees: Array<{ id: string }>;
};

type BallotRow = {
  ballotId: string;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: string;
  createdAt: string;
};

type EvaluatedBallot = {
  inviteeId: string;
  memberId: string;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: Array<{ memberIDs: string[] }>;
  createdAt: string;
};

function groupsSatisfied(
  groups: Array<{ memberIDs: string[] }>,
  attendingMemberIds: ReadonlySet<string>,
): boolean {
  return groups.every((group) =>
    group.memberIDs.some((memberId) => attendingMemberIds.has(memberId)),
  );
}

async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/gu, "");
}

async function loadLatestBallots(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionEvent,
): Promise<EvaluatedBallot[]> {
  const rows = await db
    .prepare(
      `SELECT ballot_id AS ballotId,
              response,
              minimum_participants AS minimumParticipants,
              required_groups AS requiredGroups,
              created_at AS createdAt
       FROM ballot_revisions AS ballot
       WHERE event_id = ?
         AND revision = (
           SELECT MAX(candidate.revision)
           FROM ballot_revisions AS candidate
           WHERE candidate.ballot_id = ballot.ballot_id
         )`,
    )
    .bind(event.id)
    .all<BallotRow>();
  const rowsByBallotId = new Map(rows.results.map((row) => [row.ballotId, row]));
  const mapped = await Promise.all(event.invitees.map(async ({ id: inviteeId }) => {
    const [ballotId, memberId] = await Promise.all([
      deriveBallotId(bindings, event.id, inviteeId),
      deriveBallotMemberId(bindings, event.id, inviteeId),
    ]);
    const row = rowsByBallotId.get(ballotId);
    if (!row) return null;
    let requiredGroups: Array<{ memberIDs: string[] }> = [];
    try {
      const parsed = JSON.parse(row.requiredGroups) as unknown;
      if (Array.isArray(parsed)) {
        requiredGroups = parsed.flatMap((group) => {
          if (!group || typeof group !== "object" || Array.isArray(group)) return [];
          const memberIDs = (group as { memberIDs?: unknown }).memberIDs;
          return Array.isArray(memberIDs) && memberIDs.every((member) => typeof member === "string")
            ? [{ memberIDs: memberIDs as string[] }]
            : [];
        });
      }
    } catch {
      // A malformed historical ballot is treated as a non-going response. It
      // must never make the event or later roster edits unrecoverable.
      return null;
    }
    return {
      inviteeId,
      memberId,
      response: row.response,
      minimumParticipants: row.minimumParticipants,
      requiredGroups,
      createdAt: row.createdAt,
    } satisfies EvaluatedBallot;
  }));
  return mapped.filter((ballot): ballot is EvaluatedBallot => ballot !== null);
}

async function persistResolution(
  db: D1Database,
  eventId: string,
  inputDigest: string,
  resolution: EventResolution,
  nowIso: string,
): Promise<void> {
  const attendingMemberIds = resolution.status === "confirmed"
    ? JSON.stringify(resolution.attendingMemberIds ?? [])
    : null;
  const resolvedAt = resolution.status === "pending" ? null : resolution.resolvedAt;
  await db
    .prepare(
      `INSERT INTO event_resolutions
        (event_id, policy_hash, status, batch_hash, attending_member_ids,
         resolved_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(event_id) DO UPDATE SET
         policy_hash = excluded.policy_hash,
         status = CASE
           WHEN event_resolutions.status = 'confirmed' THEN event_resolutions.status
           ELSE excluded.status
         END,
         batch_hash = CASE
           WHEN event_resolutions.status = 'confirmed' THEN event_resolutions.batch_hash
           ELSE excluded.batch_hash
         END,
         attending_member_ids = CASE
           WHEN event_resolutions.status = 'confirmed'
             THEN event_resolutions.attending_member_ids
           ELSE excluded.attending_member_ids
         END,
         resolved_at = CASE
           WHEN event_resolutions.status = 'confirmed' THEN event_resolutions.resolved_at
           ELSE excluded.resolved_at
         END,
         updated_at = excluded.updated_at`,
    )
    .bind(
      eventId,
      inputDigest,
      resolution.status,
      resolution.status === "pending" ? null : inputDigest,
      attendingMemberIds,
      resolvedAt,
      nowIso,
      nowIso,
    )
    .run();
}

/**
 * Evaluates protocol-v2 ballots directly. Identity records are used only to
 * derive stable event-scoped IDs; ballot rows remain unlinked to accounts,
 * names, phone numbers, invite tokens, and sessions.
 */
export async function getSimpleEventResolution(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionEvent,
  nowIso = new Date().toISOString(),
): Promise<EventResolution | null> {
  if (!event.invitationsSent || !event.rsvpDeadline) return null;

  const stored = await db
    .prepare(
      `SELECT status, attending_member_ids AS attendingMemberIds,
              resolved_at AS resolvedAt
       FROM event_resolutions WHERE event_id = ?`,
    )
    .bind(event.id)
    .first<{ status: string; attendingMemberIds: string | null; resolvedAt: string | null }>();

  const ballots = await loadLatestBallots(db, bindings, event);
  const memberIdByInviteeId = new Map(
    await Promise.all(event.invitees.map(async ({ id }) => [
      id,
      await deriveBallotMemberId(bindings, event.id, id),
    ] as const)),
  );
  const ballotByInviteeId = new Map(ballots.map((ballot) => [ballot.inviteeId, ballot]));
  if (stored?.status === "confirmed" && stored.resolvedAt) {
    // Confirmation is terminal, but rebuild the presentation-only guest states
    // from the immutable roster and latest ballots so every read has the same
    // useful shape as the confirming request.
    const attendingMemberIds = JSON.parse(stored.attendingMemberIds ?? "[]") as string[];
    const attendingInviteeIds = new Set(attendingMemberIds.filter((id) => id !== "host"));
    return {
      status: "confirmed",
      attendingMemberIds,
      attendanceRevealed: true,
      guestStates: event.invitees.map(({ id }) => {
        const ballot = ballotByInviteeId.get(id);
        return {
          memberId: id,
          status: attendingInviteeIds.has(id)
            ? "going"
            : ballot
              ? "cant_commit"
              : "no_response",
          missedDeadline: false,
        };
      }),
      resolvedAt: stored.resolvedAt,
    };
  }
  const attending = new Set(
    ballots.filter((ballot) => ballot.response === "going").map((ballot) => ballot.memberId),
  );
  let changed = true;
  while (changed) {
    changed = false;
    const participantCount = attending.size + 1;
    for (const ballot of ballots) {
      if (!attending.has(ballot.memberId)) continue;
      if (
        ballot.minimumParticipants === null ||
        ballot.minimumParticipants > participantCount ||
        !groupsSatisfied(ballot.requiredGroups, attending)
      ) {
        attending.delete(ballot.memberId);
        changed = true;
      }
    }
  }

  const hostGroups = event.requiredGroups.map((group) => ({
    memberIDs: group.memberIDs.flatMap((inviteeId) => {
      const memberId = memberIdByInviteeId.get(inviteeId);
      return memberId ? [memberId] : [];
    }),
  }));
  const confirmed = attending.size + 1 >= event.minimumParticipants
    && groupsSatisfied(hostGroups, attending);
  const attendingInviteeIds = event.invitees
    .filter(({ id }) => {
      const memberId = memberIdByInviteeId.get(id);
      return memberId ? attending.has(memberId) : false;
    })
    .map(({ id }) => id);
  const inputDigest = await digest(JSON.stringify({
    protocolVersion: 2,
    eventId: event.id,
    minimumParticipants: event.minimumParticipants,
    requiredGroups: event.requiredGroups,
    inviteeIds: event.invitees.map(({ id }) => id),
    ballots: ballots.map((ballot) => ({
      memberId: ballot.memberId,
      response: ballot.response,
      minimumParticipants: ballot.minimumParticipants,
      requiredGroups: ballot.requiredGroups,
      createdAt: ballot.createdAt,
    })),
  }));

  let resolution: EventResolution;
  if (confirmed) {
    resolution = {
      status: "confirmed",
      attendingMemberIds: ["host", ...attendingInviteeIds],
      attendanceRevealed: true,
      guestStates: event.invitees.map(({ id }) => {
        const ballot = ballotByInviteeId.get(id);
        const memberId = memberIdByInviteeId.get(id)!;
        return {
          memberId: id,
          status: ballot?.response === "cant_commit"
            ? "cant_commit"
            : attending.has(memberId)
              ? "going"
              : ballot
                ? "cant_commit"
                : "no_response",
          missedDeadline: false,
        };
      }),
      resolvedAt: nowIso,
    };
  } else if (nowIso >= event.rsvpDeadline) {
    resolution = { status: "not_confirmed", resolvedAt: nowIso };
  } else {
    resolution = { status: "pending" };
  }
  await persistResolution(db, event.id, inputDigest, resolution, nowIso);
  if (resolution.status !== "pending") {
    try {
      await sendResolutionTransitionNotifications(
        db,
        bindings,
        event,
        inputDigest,
        resolution.status,
      );
    } catch (error) {
      console.error("Herd resolution notification failed", {
        eventId: event.id,
        error: error instanceof Error ? error.message : "unknown_error",
      });
    }
  }
  return resolution;
}
