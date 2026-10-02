import type { HerdBindings } from "@/db";
import { acceptsAttendance } from "@/lib/attendance-window";
import { deriveBallotId } from "./ballot-identifiers";
import { getEventById } from "./events";
import { ApiError } from "./http";
import { getSimpleEventResolution } from "./simple-resolutions";

/** Only the verified Twilio handler may call this. Unanswered invited phones
 * can reply after a host's explicit SMS follow-up. Confirmed yes is final.
 * The normal client commitment rule and anonymous ballot storage stay intact. */
export async function saveSmsBallot(db: D1Database, bindings: HerdBindings,
  eventId: string, inviteeId: string, messageHash: string, response: "going" | "cant_commit") {
  const event = await getEventById(db, eventId);
  if (!event || !event.invitees.some((guest) => guest.id === inviteeId)) {
    throw new ApiError(404, "invite_not_found", "The invitation is no longer available.");
  }
  const receipt = await db.prepare("SELECT event_id FROM sms_rsvp_receipts WHERE message_hash = ?").bind(messageHash).first();
  if (receipt) {
    await getSimpleEventResolution(db, bindings, event);
    return { duplicate: true, title: event.title };
  }
  const resolution = await db.prepare("SELECT status, attending_member_ids AS attendingMemberIds FROM event_resolutions WHERE event_id = ?").bind(eventId).first<{ status: string; attendingMemberIds: string | null }>();
  if (resolution?.status !== "confirmed" || !acceptsAttendance(event, resolution.status)) {
    throw new ApiError(409, "rsvp_closed", "Text replies are closed for this event.");
  }
  const ballotId = await deriveBallotId(bindings, eventId, inviteeId);
  // A newly saved unconditional yes is already binding even if its projection
  // has not finished updating in another worker.
  const unconditionalYes = await db.prepare(`SELECT 1 FROM ballot_revisions
    WHERE ballot_id = ? AND response = 'going' AND minimum_participants = 2
      AND required_groups = '[]' LIMIT 1`).bind(ballotId).first();
  const committed = (JSON.parse(resolution.attendingMemberIds ?? "[]") as string[]).includes(inviteeId) || Boolean(unconditionalYes);
  if (committed && response === "cant_commit") {
    throw new ApiError(409, "attendance_already_committed", "Your attendance is confirmed and cannot be changed to no.");
  }
  if (committed) {
    await db.prepare("INSERT OR IGNORE INTO sms_rsvp_receipts (message_hash, event_id, created_at) VALUES (?, ?, ?)")
      .bind(messageHash, eventId, new Date().toISOString()).run();
    await getSimpleEventResolution(db, bindings, event);
    return { duplicate: false, title: event.title };
  }
  const currentRevision = await db.prepare("SELECT COALESCE(MAX(revision), 0) AS revision FROM ballot_revisions WHERE ballot_id = ?").bind(ballotId).first<number>("revision") ?? 0;
  const revision = currentRevision + 1;
  const minimum = response === "going" ? 2 : null;
  const now = new Date().toISOString();
  const content = JSON.stringify({ protocolVersion: 2, keyVersion: 1, eventId, ballotId, revision, response, minimumParticipants: minimum, requiredGroups: [] });
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
  const contentDigest = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
  // A receipt and its anonymous ballot revision commit together. Retries cannot
  // replay an earlier choice over a later reply, including after a worker crash.
  const results = await db.batch([
    db.prepare(`INSERT INTO ballot_revisions
      (ballot_id, revision, protocol_version, key_version, event_id, response,
       minimum_participants, required_groups, source, correction_reason, content_digest, created_at)
      SELECT ?, ?, 2, 1, ?, ?, ?, '[]', 'user', NULL, ?, ?
      WHERE (SELECT COALESCE(MAX(revision), 0) FROM ballot_revisions WHERE ballot_id = ?) = ?
        AND NOT EXISTS (SELECT 1 FROM sms_rsvp_receipts WHERE message_hash = ?)
        AND (? = 'going' OR (NOT EXISTS (
          SELECT 1 FROM event_resolutions r, json_each(r.attending_member_ids) member
          WHERE r.event_id = ? AND r.status = 'confirmed' AND member.value = ?
        ) AND NOT EXISTS (
          SELECT 1 FROM ballot_revisions WHERE ballot_id = ? AND response = 'going'
            AND minimum_participants = 2 AND required_groups = '[]'
        )))`)
      .bind(ballotId, revision, eventId, response, minimum, contentDigest, now, ballotId, currentRevision, messageHash, response, eventId, inviteeId, ballotId),
    db.prepare("INSERT INTO sms_rsvp_receipts (message_hash, event_id, created_at) SELECT ?, ?, ? WHERE changes() = 1")
      .bind(messageHash, eventId, now),
  ]);
  if (results[0].meta.changes !== 1) {
    const duplicate = await db.prepare("SELECT event_id FROM sms_rsvp_receipts WHERE message_hash = ?").bind(messageHash).first();
    if (!duplicate) throw new ApiError(503, "event_busy", "Your reply could not be saved. Please try again.");
  }
  await getSimpleEventResolution(db, bindings, event, now);
  return { duplicate: results[0].meta.changes !== 1, title: event.title };
}
