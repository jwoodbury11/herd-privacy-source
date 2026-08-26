import type { HerdBindings } from "@/db";

import { getAuthConfig, getInvitationDeliveryConfig } from "./config";
import { randomUuid } from "./crypto";
import { ApiError } from "./http";
import { openSealedInviteToken } from "./invite-tokens";
import type { CanonicalEvent } from "./types";

const DISPATCH_TIMEOUT_MS = 10_000;
const STALE_DISPATCH_MS = 2 * 60_000;
const TWILIO_MESSAGES_ORIGIN = "https://api.twilio.com";

export const invitationDeliveryStatuses = [
  "pending",
  "dispatching",
  "sent",
  "failed",
  "unknown",
  "suppressed",
] as const;

export type InvitationDeliveryStatus =
  (typeof invitationDeliveryStatuses)[number];

export type InvitationDeliverySummary = {
  status: "in_progress" | "complete" | "attention_needed" | "suppressed";
  total: number;
  counts: Record<InvitationDeliveryStatus, number>;
  guests: {
    inviteeId: string;
    displayName: string;
    status: InvitationDeliveryStatus;
  }[];
};

type DeliveryDispatchRow = {
  id: string;
  eventId: string;
  inviteeId: string;
  phoneNumber: string;
  tokenCiphertext: string | null;
  tokenNonce: string | null;
  tokenStorageVersion: number | null;
  hostName: string;
  title: string;
  eventDate: string | null;
  eventTimeZone: string | null;
  rsvpDeadline: string | null;
};

type InvitationDispatchOptions = {
  replyResetInviteeIds?: ReadonlySet<string>;
};

type DeliveryProjectionRow = {
  eventId: string;
  inviteeId: string;
  displayName: string;
  status: InvitationDeliveryStatus;
};

type TwilioMessageResponse = {
  sid?: unknown;
  status?: unknown;
  code?: unknown;
};

function emptyCounts(): Record<InvitationDeliveryStatus, number> {
  return {
    pending: 0,
    dispatching: 0,
    sent: 0,
    failed: 0,
    unknown: 0,
    suppressed: 0,
  };
}

function summarizeRows(rows: DeliveryProjectionRow[]): InvitationDeliverySummary | null {
  if (rows.length === 0) return null;
  const counts = emptyCounts();
  for (const row of rows) counts[row.status] += 1;
  let status: InvitationDeliverySummary["status"];
  if (counts.failed > 0 || counts.unknown > 0) status = "attention_needed";
  else if (counts.pending > 0 || counts.dispatching > 0) status = "in_progress";
  else if (counts.suppressed === rows.length) status = "suppressed";
  else status = "complete";
  return {
    status,
    total: rows.length,
    counts,
    guests: rows.map((row) => ({
      inviteeId: row.inviteeId,
      displayName: row.displayName,
      status: row.status,
    })),
  };
}

export function assertInvitationDeliveryReady(
  bindings: HerdBindings,
  event: Pick<CanonicalEvent, "invitees">,
): void {
  if (event.invitees.length > 0 && !getInvitationDeliveryConfig(bindings)) {
    throw new ApiError(
      503,
      "invitation_delivery_unavailable",
      "Invitation messaging is not configured. The event remains a draft.",
    );
  }
}

export function prepareInvitationDeliveryStatements(
  db: D1Database,
  bindings: HerdBindings,
  event: Pick<CanonicalEvent, "id" | "invitees">,
  nowIso: string,
): D1PreparedStatement[] {
  return event.invitees.map((invitee) => {
    return db
      .prepare(
        `INSERT INTO invitation_deliveries
          (id, event_id, invitee_id, status, provider_message_sid, provider_status,
           attempt_count, dispatch_started_at, sent_at, failed_at, last_error_code,
           last_error_message, suppressed_reason, created_at, updated_at)
         VALUES (?, ?, ?, ?, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, ?, ?, ?)
         ON CONFLICT(event_id, invitee_id) DO NOTHING`,
      )
      .bind(
        randomUuid(),
        event.id,
        invitee.id,
        "pending",
        null,
        nowIso,
        nowIso,
      );
  });
}

export async function markStaleInvitationDispatchesUnknown(
  db: D1Database,
  eventId: string,
  now = new Date(),
): Promise<void> {
  const cutoff = new Date(now.getTime() - STALE_DISPATCH_MS).toISOString();
  await db
    .prepare(
      `UPDATE invitation_deliveries
       SET status = 'unknown',
           failed_at = ?,
           last_error_code = 'dispatch_interrupted',
           last_error_message = 'Delivery may have been accepted; it will not be retried automatically.',
           updated_at = ?
       WHERE event_id = ?
         AND status = 'dispatching'
         AND dispatch_started_at < ?`,
    )
    .bind(now.toISOString(), now.toISOString(), eventId, cutoff)
    .run();
}

export async function getInvitationDeliverySummaries(
  db: D1Database,
  eventIds: string[],
): Promise<Map<string, InvitationDeliverySummary>> {
  const summaries = new Map<string, InvitationDeliverySummary>();
  if (eventIds.length === 0) return summaries;
  await Promise.all(
    eventIds.map((eventId) => markStaleInvitationDispatchesUnknown(db, eventId)),
  );
  const placeholders = eventIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT invitation_deliveries.event_id AS eventId,
              invitation_deliveries.invitee_id AS inviteeId,
              invitees.display_name AS displayName,
              invitation_deliveries.status AS status
       FROM invitation_deliveries
       JOIN invitees ON invitees.id = invitation_deliveries.invitee_id
       WHERE invitation_deliveries.event_id IN (${placeholders})
       ORDER BY invitees.created_at ASC, invitees.id ASC`,
    )
    .bind(...eventIds)
    .all<DeliveryProjectionRow>();
  const rowsByEvent = new Map<string, DeliveryProjectionRow[]>();
  for (const row of result.results) {
    const rows = rowsByEvent.get(row.eventId) ?? [];
    rows.push(row);
    rowsByEvent.set(row.eventId, rows);
  }
  for (const [eventId, rows] of rowsByEvent) {
    const summary = summarizeRows(rows);
    if (summary) summaries.set(eventId, summary);
  }
  return summaries;
}

export async function getInvitationDeliverySummary(
  db: D1Database,
  eventId: string,
): Promise<InvitationDeliverySummary | null> {
  return (await getInvitationDeliverySummaries(db, [eventId])).get(eventId) ?? null;
}

function invitationDate(value: string | null, timeZone: string | null): string {
  if (!value) return "date to be announced";
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: timeZone ?? "UTC",
  }).format(new Date(value));
}

export function invitationMessageBody(
  event: Pick<CanonicalEvent, "hostName" | "title" | "eventDate" | "eventTimeZone">,
  invitationUrl: string,
  options: { replyReset?: boolean } = {},
): string {
  if (options.replyReset) {
    return `${invitationUrl}\n${event.hostName} updated ${event.title}. Open Herd to review the guest list change and send your private reply again. One-time message sent at ${event.hostName}’s request. Reply STOP to opt out; HELP for help. Msg & data rates may apply.`;
  }
  return `${invitationUrl}\n${event.hostName} invited you to ${event.title} — ${invitationDate(event.eventDate, event.eventTimeZone)}. Open the invitation and reply privately. One-time message sent at ${event.hostName}’s request. Reply STOP to opt out; HELP for help. Msg & data rates may apply.`;
}

async function updateDispatchResult(
  db: D1Database,
  deliveryId: string,
  status: "sent" | "failed" | "unknown",
  values: {
    providerMessageSid?: string | null;
    providerStatus?: string | null;
    errorCode?: string | null;
    errorMessage?: string | null;
  },
): Promise<void> {
  const nowIso = new Date().toISOString();
  await db
    .prepare(
      `UPDATE invitation_deliveries
       SET status = ?,
           provider_message_sid = ?,
           provider_status = ?,
           sent_at = ?,
           failed_at = ?,
           last_error_code = ?,
           last_error_message = ?,
           updated_at = ?
       WHERE id = ? AND status = 'dispatching'`,
    )
    .bind(
      status,
      values.providerMessageSid ?? null,
      values.providerStatus ?? null,
      status === "sent" ? nowIso : null,
      status === "sent" ? null : nowIso,
      values.errorCode ?? null,
      values.errorMessage ?? null,
      nowIso,
      deliveryId,
    )
    .run();
}

async function acquirePendingDelivery(
  db: D1Database,
  deliveryId: string,
  nowIso: string,
): Promise<boolean> {
  const acquired = await db
    .prepare(
      `UPDATE invitation_deliveries
       SET status = 'dispatching',
           attempt_count = attempt_count + 1,
           dispatch_started_at = ?,
           updated_at = ?
       WHERE id = ? AND status = 'pending'`,
    )
    .bind(nowIso, nowIso, deliveryId)
    .run();
  return (acquired.meta.changes ?? 0) === 1;
}

async function dispatchOne(
  db: D1Database,
  bindings: HerdBindings,
  row: DeliveryDispatchRow,
  options: { replyReset?: boolean } = {},
): Promise<void> {
  const nowIso = new Date().toISOString();
  if (!row.rsvpDeadline || row.rsvpDeadline <= nowIso) {
    if (!(await acquirePendingDelivery(db, row.id, nowIso))) return;
    await updateDispatchResult(db, row.id, "failed", {
      errorCode: "rsvp_closed_before_delivery",
      errorMessage: "The reply deadline passed before this invitation could be delivered.",
    });
    return;
  }

  const config = getInvitationDeliveryConfig(bindings);
  if (!config) {
    throw new ApiError(
      503,
      "invitation_delivery_unavailable",
      "Invitation messaging is not configured. Try again shortly.",
    );
  }

  const dispatchStartedAt = new Date().toISOString();
  if (row.rsvpDeadline <= dispatchStartedAt) {
    if (!(await acquirePendingDelivery(db, row.id, dispatchStartedAt))) return;
    await updateDispatchResult(db, row.id, "failed", {
      errorCode: "rsvp_closed_before_delivery",
      errorMessage: "The reply deadline passed before this invitation could be delivered.",
    });
    return;
  }
  if (!(await acquirePendingDelivery(db, row.id, dispatchStartedAt))) return;

  let token: string;
  try {
    token = await openSealedInviteToken(
      getAuthConfig(bindings).pepper,
      row.eventId,
      row.inviteeId,
      row,
    );
  } catch {
    await updateDispatchResult(db, row.id, "failed", {
      errorCode: "invite_token_unavailable",
      errorMessage: "The private invitation link could not be prepared.",
    });
    return;
  }

  const invitationUrl = `${config.publicAppUrl}/invite/${encodeURIComponent(token)}`;
  const body = invitationMessageBody(row, invitationUrl, options);
  if (body.length > 1_600) {
    await updateDispatchResult(db, row.id, "failed", {
      errorCode: "message_too_long",
      errorMessage: "The invitation message exceeds the provider limit.",
    });
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MS);
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
          To: row.phoneNumber,
          MessagingServiceSid: config.twilio.messagingServiceSid,
          Body: body,
        }),
        signal: controller.signal,
      },
    );
    const payload = (await response.json().catch(() => ({}))) as TwilioMessageResponse;
    const providerCode =
      typeof payload.code === "string" || typeof payload.code === "number"
        ? String(payload.code).slice(0, 80)
        : `http_${response.status}`;
    if (!response.ok) {
      if (response.status >= 500) {
        await updateDispatchResult(db, row.id, "unknown", {
          errorCode: providerCode,
          errorMessage: "The provider response was ambiguous; this invitation will not retry automatically.",
        });
      } else {
        await updateDispatchResult(db, row.id, "failed", {
          errorCode: providerCode,
          errorMessage: "The messaging provider rejected this invitation.",
        });
      }
      return;
    }

    const providerMessageSid =
      typeof payload.sid === "string" && /^SM[0-9a-fA-F]{32}$/u.test(payload.sid)
        ? payload.sid
        : null;
    if (!providerMessageSid) {
      await updateDispatchResult(db, row.id, "unknown", {
        errorCode: "invalid_provider_receipt",
        errorMessage: "The provider response was ambiguous; this invitation will not retry automatically.",
      });
      return;
    }
    await updateDispatchResult(db, row.id, "sent", {
      providerMessageSid,
      providerStatus:
        typeof payload.status === "string" ? payload.status.slice(0, 80) : null,
    });
  } catch {
    await updateDispatchResult(db, row.id, "unknown", {
      errorCode: "provider_transport_unknown",
      errorMessage: "Delivery may have been accepted; this invitation will not retry automatically.",
    });
  } finally {
    clearTimeout(timeout);
  }
}

export async function dispatchEventInvitations(
  db: D1Database,
  bindings: HerdBindings,
  eventId: string,
  options: InvitationDispatchOptions = {},
): Promise<InvitationDeliverySummary | null> {
  const result = await db
    .prepare(
      `SELECT invitation_deliveries.id,
              invitation_deliveries.event_id AS eventId,
              invitation_deliveries.invitee_id AS inviteeId,
              invitees.phone_number AS phoneNumber,
              invitees.token_ciphertext AS tokenCiphertext,
              invitees.token_nonce AS tokenNonce,
              invitees.token_storage_version AS tokenStorageVersion,
              events.host_name AS hostName,
              events.title,
              events.event_date AS eventDate,
              events.event_time_zone AS eventTimeZone,
              events.rsvp_deadline AS rsvpDeadline
       FROM invitation_deliveries
       JOIN invitees ON invitees.id = invitation_deliveries.invitee_id
       JOIN events ON events.id = invitation_deliveries.event_id
       WHERE invitation_deliveries.event_id = ?
         AND invitation_deliveries.status = 'pending'
       ORDER BY invitation_deliveries.created_at ASC, invitation_deliveries.id ASC`,
    )
    .bind(eventId)
    .all<DeliveryDispatchRow>();
  await Promise.all(result.results.map((row) => dispatchOne(db, bindings, row, {
    replyReset: options.replyResetInviteeIds?.has(row.inviteeId),
  })));
  return getInvitationDeliverySummary(db, eventId);
}
