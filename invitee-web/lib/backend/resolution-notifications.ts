import type { HerdBindings } from "@/db";

import { getInvitationDeliveryConfig } from "./config";
import { randomUuid } from "./crypto";

const TWILIO_MESSAGES_ORIGIN = "https://api.twilio.com";
const DISPATCH_TIMEOUT_MILLISECONDS = 10_000;

type ResolutionStatus = "confirmed" | "not_confirmed";

type RecipientRow = { phoneNumber: string };

function messageBody(title: string, status: ResolutionStatus): string {
  return status === "confirmed"
    ? `Herd: ${title} is confirmed. Replies can still change; guest statuses stay private until the deadline.`
    : `Herd: ${title} is no longer confirmed. Replies can still change.`;
}

export async function sendResolutionTransitionNotifications(
  db: D1Database,
  bindings: HerdBindings,
  event: { id: string; title?: string },
  batchHash: string,
  status: ResolutionStatus,
): Promise<void> {
  const previous = await db
    .prepare(
      `SELECT status
       FROM resolution_notifications
       WHERE event_id = ?
       ORDER BY created_at DESC, id DESC
       LIMIT 1`,
    )
    .bind(event.id)
    .first<{ status: ResolutionStatus }>();
  if (previous?.status === status || (!previous && status === "not_confirmed")) return;

  const recipients = await db
    .prepare(
      `SELECT users.phone_number AS phoneNumber
       FROM events
       JOIN users ON users.id = events.host_user_id
       WHERE events.id = ?
       UNION
       SELECT invitees.phone_number AS phoneNumber
       FROM invitees
       WHERE invitees.event_id = ?
         AND EXISTS (
           SELECT 1 FROM response_envelopes
           WHERE response_envelopes.invitee_id = invitees.id
         )
       ORDER BY phoneNumber ASC`,
    )
    .bind(event.id, event.id)
    .all<RecipientRow>();
  const config = getInvitationDeliveryConfig(bindings);
  const nowIso = new Date().toISOString();
  for (const recipient of recipients.results) {
    const id = randomUuid();
    const inserted = await db
      .prepare(
        `INSERT INTO resolution_notifications
          (id, event_id, batch_hash, status, phone_number, delivery_status,
           provider_message_sid, error_code, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
         ON CONFLICT(event_id, batch_hash, phone_number) DO NOTHING`,
      )
      .bind(
        id,
        event.id,
        batchHash,
        status,
        recipient.phoneNumber,
        "dispatching",
        nowIso,
        nowIso,
      )
      .run();
    if ((inserted.meta.changes ?? 0) !== 1) continue;
    if (!config) {
      await db
        .prepare(
          `UPDATE resolution_notifications
           SET delivery_status = 'failed', error_code = 'messaging_unavailable', updated_at = ?
           WHERE id = ?`,
        )
        .bind(new Date().toISOString(), id)
        .run();
      continue;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MILLISECONDS);
    try {
      const response = await fetch(
        `${TWILIO_MESSAGES_ORIGIN}/2010-04-01/Accounts/${encodeURIComponent(config.twilio.accountSid)}/Messages.json`,
        {
          method: "POST",
          headers: {
            Authorization: `Basic ${btoa(`${config.twilio.apiKeySid}:${config.twilio.apiKeySecret}`)}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            To: recipient.phoneNumber,
            MessagingServiceSid: config.twilio.messagingServiceSid,
            Body: messageBody(event.title || "Your event", status),
          }),
          signal: controller.signal,
        },
      );
      const payload = (await response.json().catch(() => ({}))) as {
        sid?: unknown;
        code?: unknown;
      };
      const providerSid = typeof payload.sid === "string" ? payload.sid.slice(0, 80) : null;
      const errorCode = response.ok
        ? null
        : typeof payload.code === "string" || typeof payload.code === "number"
          ? String(payload.code).slice(0, 80)
          : `http_${response.status}`;
      await db
        .prepare(
          `UPDATE resolution_notifications
           SET delivery_status = ?, provider_message_sid = ?, error_code = ?, updated_at = ?
           WHERE id = ? AND delivery_status = 'dispatching'`,
        )
        .bind(
          response.ok ? "sent" : response.status >= 500 ? "unknown" : "failed",
          providerSid,
          errorCode,
          new Date().toISOString(),
          id,
        )
        .run();
    } catch {
      await db
        .prepare(
          `UPDATE resolution_notifications
           SET delivery_status = 'unknown', error_code = 'request_ambiguous', updated_at = ?
           WHERE id = ? AND delivery_status = 'dispatching'`,
        )
        .bind(new Date().toISOString(), id)
        .run();
    } finally {
      clearTimeout(timeout);
    }
  }
}
