import type { HerdBindings } from "@/db";
import { acceptsAttendance, attendanceClosesAt } from "@/lib/attendance-window";
import { getInvitationDeliveryConfig, getAuthConfig } from "./config";
import { pepperedHash, randomUuid } from "./crypto";
import { getEventById } from "./events";
import { deriveBallotId } from "./ballot-identifiers";
import { ApiError } from "./http";
import { saveSmsBallot } from "./sms-ballots";
import { smsResponse } from "./twilio-webhook";

export function smsTestPhone(bindings: HerdBindings): string | null {
  const phone = bindings.HERD_SMS_RSVP_TEST_PHONE?.trim();
  if (!phone) return null;
  if (!/^\+[1-9]\d{7,14}$/u.test(phone)) throw new ApiError(503, "invalid_sms_test_phone", "The SMS test recipient is misconfigured.");
  return phone;
}

export function smsReminderMessage(event: { hostName: string; title: string; eventDate: string | null; eventTimeZone?: string | null; locationName: string }, now = new Date()) {
  const timeZone = event.eventTimeZone || "UTC";
  const date = new Date(event.eventDate!);
  const calendarDay = (value: Date) => {
    const parts = new Intl.DateTimeFormat("en-US", { timeZone, year: "numeric", month: "numeric", day: "numeric" }).formatToParts(value);
    const part = (type: string) => Number(parts.find((p) => p.type === type)!.value);
    return Date.UTC(part("year"), part("month") - 1, part("day")) / 86_400_000;
  };
  const tomorrow = calendarDay(date) - calendarDay(now) === 1 ? "tomorrow, " : "";
  const day = new Intl.DateTimeFormat("en-US", { timeZone, weekday: "long", month: "long", day: "numeric" }).format(date);
  const time = new Intl.DateTimeFormat("en-US", { timeZone, hour: "numeric", minute: "2-digit" }).format(date).replace(/:00(?=\s)/u, "");
  const location = event.locationName ? ` at ${event.locationName}` : "";
  return `Thanks for trying out the eng prototype test of Herd!\n\n${event.hostName.trim()}’s event “${event.title}” is ${tomorrow}${day} at ${time}${location}, and we haven’t received your response yet.\n\nHerd is thoughtfully designed to remove all the downsides to answering honestly. However, your response rate is visible on your profile to encourage more fun events.\n\nIf it’s easier, you can also reply to this text to keep your Herd response rate at 100%:\n\n1: I’m down\n2: Can’t come`;
}

export async function handleSmsRsvp(db: D1Database, bindings: HerdBindings, params: URLSearchParams): Promise<Response> {
  // A prepared release must not send automatic replies before explicit activation.
  if (bindings.HERD_SMS_RSVP_ENABLED !== "true") return smsResponse();
  const testPhone = smsTestPhone(bindings);
  if (testPhone && params.get("From") !== testPhone) return smsResponse();
  const body = (params.get("Body") ?? "").trim();
  // Twilio owns its standard opt-out/help handling. Never turn these into RSVP writes.
  if (params.has("OptOutType") || /^(stop|stopall|unsubscribe|cancel|end|quit|revoke|optout|start|unstop|help|info)$/iu.test(body)) return smsResponse();
  const messageHash = await pepperedHash(getAuthConfig(bindings).pepper, "sms-rsvp-receipt", params.get("MessageSid")!);
  const existing = await db.prepare("SELECT event_id AS eventId FROM sms_rsvp_receipts WHERE message_hash = ?").bind(messageHash).first<{ eventId: string }>();
  if (existing) {
    // The earlier transaction already saved the choice. Recompute if its worker
    // failed before publishing the projection, without applying the choice again.
    const event = await getEventById(db, existing.eventId);
    if (event) {
      const { getSimpleEventResolution } = await import("./simple-resolutions");
      await getSimpleEventResolution(db, bindings, event);
    }
    return smsResponse("Herd: This reply has already been saved.");
  }
  const phoneHash = await pepperedHash(getAuthConfig(bindings).pepper, "phone", params.get("From")!);
  const now = new Date().toISOString();
  const contexts = await db.prepare(`SELECT i.event_id AS eventId, i.id AS inviteeId, e.title
    FROM sms_rsvp_prompts p JOIN invitees i ON i.id = p.invitee_id AND i.event_id = p.event_id
    JOIN events e ON e.id = i.event_id
    WHERE i.phone_hash = ? AND p.status IN ('sent', 'dispatching', 'unknown')
      AND p.created_at <= ? AND p.expires_at > ?
    GROUP BY i.event_id, i.id, e.title LIMIT 2`).bind(phoneHash, now, now)
    .all<{ eventId: string; inviteeId: string; title: string }>();
  if (contexts.results.length === 0) return smsResponse();
  if (contexts.results.length !== 1) return smsResponse("Herd: You have more than one event accepting text replies. Please update your reply in the app: " + bindings.HERD_PUBLIC_APP_URL);
  const context = contexts.results[0];
  if (body !== "1" && body !== "2") {
    return smsResponse(`Herd: For ${context.title}, reply 1 to attend or 2 if you can't come. A yes confirms your attendance.`);
  }
  try {
    const result = await saveSmsBallot(db, bindings, context.eventId, context.inviteeId, messageHash, body === "1" ? "going" : "cant_commit");
    return smsResponse(result.duplicate ? "Herd: This reply has already been saved."
      : body === "1" ? `Herd: You're confirmed Going for ${result.title}. See you there!`
        : `Herd: You're marked Can't commit for ${result.title} and won't count as attending. Reply 1 if your plans change.`);
  } catch (error) {
    if (error instanceof ApiError && error.code === "attendance_already_committed") return smsResponse("Herd: You are already confirmed Going. Confirmed attendance cannot be changed to no.");
    if (error instanceof ApiError && (error.status === 409 || error.status === 404)) return smsResponse("Herd: Text replies are closed for this event. Your attendance was not changed.");
    throw error;
  }
}

async function promptSummary(db: D1Database, eventId: string, batchId: string) {
  const rows = await db.prepare(`SELECT status, COUNT(*) AS count FROM sms_rsvp_prompts
    WHERE event_id = ? AND batch_id = ? GROUP BY status`).bind(eventId, batchId).all<{ status: string; count: number }>();
  return { batchId, counts: Object.fromEntries(rows.results.map((row) => [row.status, row.count])), total: rows.results.reduce((n, row) => n + row.count, 0) };
}

async function isUnanswered(db: D1Database, bindings: HerdBindings, eventId: string, inviteeId: string) {
  const ballotId = await deriveBallotId(bindings, eventId, inviteeId);
  const found = await db.prepare(`SELECT 1 AS found WHERE
    EXISTS (SELECT 1 FROM ballot_revisions WHERE event_id = ? AND ballot_id = ?)
    OR EXISTS (SELECT 1 FROM response_envelopes WHERE event_id = ? AND invitee_id = ?)
    OR EXISTS (SELECT 1 FROM event_resolutions r, json_each(r.attending_member_ids) member
      WHERE r.event_id = ? AND member.value = ?)`)
    .bind(eventId, ballotId, eventId, inviteeId, eventId, inviteeId).first();
  return !found;
}

export async function prepareSmsRsvp(db: D1Database, bindings: HerdBindings, eventId: string, audience: "unanswered") {
  const event = await getEventById(db, eventId);
  if (!event) throw new ApiError(404, "event_not_found", "The event was not found.");
  const resolution = await db.prepare("SELECT status, attending_member_ids AS attendingMemberIds FROM event_resolutions WHERE event_id = ?")
    .bind(eventId).first<{ status: string; attendingMemberIds: string | null }>();
  if (resolution?.status !== "confirmed" || !acceptsAttendance(event, resolution.status) || !event.eventDate) {
    throw new ApiError(409, "sms_rsvp_closed", "Text follow-ups require an open, confirmed event with a start time.");
  }
  if (audience !== "unanswered") throw new ApiError(400, "invalid_audience", "Only unanswered guests can receive this follow-up.");
  const testPhone = smsTestPhone(bindings);
  const eligibility = await Promise.all(event.invitees.map(async (guest) => {
    if (testPhone && guest.phoneNumber !== testPhone) return null;
    return await isUnanswered(db, bindings, event.id, guest.id) ? guest : null;
  }));
  const recipients = eligibility.filter((guest): guest is NonNullable<typeof guest> => guest !== null);
  const message = smsReminderMessage(event);
  if (message.length > 1_600) throw new ApiError(400, "sms_too_long", "The event details are too long for an SMS reminder.");
  return { event, recipients, message, expiresAt: new Date(attendanceClosesAt(event, resolution.status)!).toISOString() };
}

export async function sendSmsRsvp(db: D1Database, bindings: HerdBindings, eventId: string, audience: "unanswered", batchId: string, approvedMessage?: string) {
  if (bindings.HERD_SMS_RSVP_ENABLED !== "true") throw new ApiError(409, "sms_rsvp_disabled", "SMS follow-ups have not been activated.");
  const config = getInvitationDeliveryConfig(bindings);
  const from = bindings.HERD_SMS_FROM_NUMBER?.trim();
  if (!config || !from || !bindings.TWILIO_AUTH_TOKEN?.trim()) throw new ApiError(503, "sms_replies_unavailable", "Text replies must be configured before sending a follow-up.");
  const existing = await promptSummary(db, eventId, batchId);
  if (existing.total > 0) return existing; // Never resend an uncertain batch.
  const prepared = await prepareSmsRsvp(db, bindings, eventId, audience);
  const message = approvedMessage ?? prepared.message;
  if (!message.trim() || message.length > 1_600) throw new ApiError(400, "invalid_sms_copy", "The message must contain between 1 and 1600 characters.");
  const now = new Date().toISOString();
  const prompts = prepared.recipients.map((recipient) => ({ id: randomUuid(), recipient }));
  if (prompts.length === 0) return existing;
  // Freeze the full audience before dispatch. Unique batch/guest rows prevent
  // two operator retries from sending the same reminder twice.
  await db.batch(prompts.map(({ id, recipient }) => db.prepare(`INSERT INTO sms_rsvp_prompts
    (id, batch_id, event_id, invitee_id, status, provider_message_sid, created_at, expires_at)
    VALUES (?, ?, ?, ?, 'pending', NULL, ?, ?)`).bind(id, batchId, eventId, recipient.id, now, prepared.expiresAt)));
  for (const { id, recipient } of prompts) {
    // Recheck at dispatch so replies submitted after preview are excluded too.
    if (!await isUnanswered(db, bindings, eventId, recipient.id)) {
      await db.prepare("UPDATE sms_rsvp_prompts SET status = 'suppressed' WHERE id = ?").bind(id).run();
      continue;
    }
    await db.prepare("UPDATE sms_rsvp_prompts SET status = 'dispatching' WHERE id = ?").bind(id).run();
    let status = "unknown";
    let providerSid: string | null = null;
    try {
      const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.twilio.accountSid)}/Messages.json`, {
        method: "POST",
        headers: { authorization: `Basic ${btoa(`${config.twilio.apiKeySid}:${config.twilio.apiKeySecret}`)}`, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ To: recipient.phoneNumber, From: from, MessagingServiceSid: config.twilio.messagingServiceSid, Body: message }),
        signal: AbortSignal.timeout(10_000),
      });
      const payload = await response.json().catch(() => ({})) as { sid?: string; status?: string };
      providerSid = typeof payload.sid === "string" && /^SM[0-9a-fA-F]{32}$/u.test(payload.sid) ? payload.sid : null;
      status = response.ok && providerSid ? "sent" : response.status >= 500 ? "unknown" : "failed";
    } catch { /* An ambiguous send is never automatically retried. */ }
    await db.prepare("UPDATE sms_rsvp_prompts SET status = ?, provider_message_sid = ? WHERE id = ?").bind(status, providerSid, id).run();
  }
  return promptSummary(db, eventId, batchId);
}
