import { getBindings, getD1 } from "@/db";
import { deriveBallotMemberId } from "@/lib/backend/ballot-identifiers";
import {
  ApiError,
  jsonResponse,
  readJsonObject,
  requireString,
  withApiErrors,
} from "@/lib/backend/http";
import { requireOperatorAuthorization } from "@/lib/backend/operator-auth";

export const dynamic = "force-dynamic";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

export async function GET(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireOperatorAuthorization(request, bindings);
    const eventId = new URL(request.url).searchParams.get("eventId")?.toLowerCase() ?? "";
    if (!UUID_PATTERN.test(eventId)) {
      throw new ApiError(400, "invalid_event_id", "A valid event ID is required.");
    }
    const db = await getD1();
    const rows = await db.prepare(
      `SELECT ballot_id AS ballotId, revision, protocol_version AS protocolVersion,
              key_version AS keyVersion, event_id AS eventId, response,
              minimum_participants AS minimumParticipants,
              required_groups AS requiredGroups, source,
              correction_reason AS correctionReason,
              content_digest AS contentDigest, created_at AS createdAt
       FROM ballot_revisions
       WHERE event_id = ?
       ORDER BY ballot_id, revision`,
    ).bind(eventId).all<Record<string, unknown>>();
    return jsonResponse({
      eventId,
      ballots: rows.results.map((row) => ({
        ...row,
        requiredGroups: JSON.parse(String(row.requiredGroups)),
      })),
    }, { headers: {
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Robots-Tag": "noindex, nofollow, noarchive",
    } });
  });
}

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireOperatorAuthorization(request, bindings);
    const payload = await readJsonObject(request);
    if (payload.action !== "append_correction") {
      throw new ApiError(400, "invalid_operator_action", "The operator action is invalid.");
    }
    const eventId = requireString(payload.eventId, "event ID", { min: 36, max: 36 }).toLowerCase();
    const ballotId = requireString(payload.ballotId, "ballot ID", { min: 43, max: 43 });
    const actor = requireString(payload.actor, "actor", { min: 2, max: 120 });
    const reason = requireString(payload.reason, "reason", { min: 8, max: 500 });
    const correlationId = requireString(payload.correlationId, "correlation ID", { min: 8, max: 120 });
    if (!UUID_PATTERN.test(eventId)) {
      throw new ApiError(400, "invalid_event_id", "A valid event ID is required.");
    }
    if (payload.response !== "going" && payload.response !== "cant_commit") {
      throw new ApiError(400, "invalid_ballot", "The corrected reply is invalid.");
    }
    const db = await getD1();
    const resolution = await db.prepare(
      "SELECT status FROM event_resolutions WHERE event_id = ?",
    ).bind(eventId).first<{ status: string }>();
    if (resolution?.status === "confirmed") {
      throw new ApiError(409, "event_already_confirmed", "Confirmed events cannot be corrected.");
    }
    const current = await db.prepare(
      `SELECT revision, content_digest AS contentDigest
       FROM ballot_revisions
       WHERE event_id = ? AND ballot_id = ?
       ORDER BY revision DESC LIMIT 1`,
    ).bind(eventId, ballotId).first<{ revision: number; contentDigest: string }>();
    if (!current) throw new ApiError(404, "ballot_not_found", "The ballot was not found.");
    const members = await db.prepare("SELECT id FROM invitees WHERE event_id = ?")
      .bind(eventId).all<{ id: string }>();
    const allowedMembers = new Set(await Promise.all(
      members.results.map(({ id }) => deriveBallotMemberId(bindings, eventId, id)),
    ));
    if (!Array.isArray(payload.requiredGroups)) {
      throw new ApiError(400, "invalid_ballot", "The corrected conditions are invalid.");
    }
    const seen = new Set<string>();
    const requiredGroups = payload.requiredGroups.map((rawGroup) => {
      if (!rawGroup || typeof rawGroup !== "object" || Array.isArray(rawGroup)) {
        throw new ApiError(400, "invalid_ballot", "A corrected condition is invalid.");
      }
      const group = rawGroup as Record<string, unknown>;
      const id = requireString(group.id, "condition ID", { min: 1, max: 120 });
      if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
        throw new ApiError(400, "invalid_ballot", "A corrected condition is invalid.");
      }
      const memberIDs = group.memberIDs.map((member) => {
        const memberId = requireString(member, "member ID", { min: 43, max: 43 });
        if (!allowedMembers.has(memberId) || seen.has(memberId)) {
          throw new ApiError(400, "invalid_ballot", "A corrected condition has an invalid member.");
        }
        seen.add(memberId);
        return memberId;
      });
      return { id, memberIDs };
    });
    const participantCount = members.results.length + 1;
    const minimumParticipants = payload.response === "going"
      ? payload.minimumParticipants
      : null;
    if (
      payload.response === "going"
        ? !Number.isInteger(minimumParticipants)
          || (minimumParticipants as number) < 2
          || (minimumParticipants as number) > participantCount
        : payload.minimumParticipants !== null || requiredGroups.length > 0
    ) {
      throw new ApiError(400, "invalid_ballot", "The corrected minimum is invalid.");
    }
    const revision = current.revision + 1;
    const createdAt = new Date().toISOString();
    const contentDigest = await sha256(JSON.stringify({
      protocolVersion: 2, keyVersion: 1, eventId, ballotId, revision,
      response: payload.response, minimumParticipants, requiredGroups,
    }));
    const actionId = crypto.randomUUID();
    await db.batch([
      db.prepare(
        `INSERT INTO ballot_revisions (
           ballot_id, revision, protocol_version, key_version, event_id,
           response, minimum_participants, required_groups, source,
           correction_reason, content_digest, created_at
         ) VALUES (?, ?, 2, 1, ?, ?, ?, ?, 'support_correction', ?, ?, ?)`,
      ).bind(
        ballotId, revision, eventId, payload.response, minimumParticipants,
        JSON.stringify(requiredGroups), reason, contentDigest, createdAt,
      ),
      db.prepare(
        `INSERT INTO ballot_operator_actions (
           id, event_id, ballot_id, action, actor, reason,
           previous_digest, next_digest, correlation_id, created_at
         ) VALUES (?, ?, ?, 'append_correction', ?, ?, ?, ?, ?, ?)`,
      ).bind(
        actionId, eventId, ballotId, actor, reason, current.contentDigest,
        contentDigest, correlationId, createdAt,
      ),
    ]);
    return jsonResponse({
      actionId, eventId, ballotId, revision, contentDigest, createdAt,
    }, { status: 201, headers: { "Cache-Control": "no-store" } });
  });
}
