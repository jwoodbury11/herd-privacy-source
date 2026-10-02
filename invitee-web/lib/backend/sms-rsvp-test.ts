import type { HerdBindings } from "@/db";
import { getAuthConfig } from "./config";
import { randomUuid } from "./crypto";
import { getEventById, putHostedEvent } from "./events";
import { ApiError } from "./http";
import { prepareSmsRsvp, smsReminderMessage, smsTestPhone } from "./sms-rsvp";
import { testAccountPhoneNumberForAlias } from "./test-accounts.mjs";

/** Seed a disposable, already-confirmed event for the explicitly allowlisted
 * test phone. Never sends invitations or confirmation notifications. */
export async function prepareSmsRsvpTest(db: D1Database, bindings: HerdBindings, sourceEventId: string, testEventId: string) {
  const phone = smsTestPhone(bindings);
  if (!phone || !getAuthConfig(bindings).testAccountAccessEnabled) {
    throw new ApiError(409, "sms_test_unavailable", "A single test number and test-account access are required.");
  }
  if (sourceEventId === testEventId) throw new ApiError(400, "invalid_test_event", "The test must use a separate event.");
  const source = await prepareSmsRsvp(db, bindings, sourceEventId, "unanswered");
  const testHost = await db.prepare("SELECT id, phone_number AS phoneNumber FROM users WHERE phone_number = ?")
    .bind(testAccountPhoneNumberForAlias("1")).first<{ id: string; phoneNumber: string }>();
  if (!testHost || testHost.phoneNumber === phone) throw new ApiError(409, "sms_test_host_unavailable", "Initialize the designated test host first.");
  const marker = `Disposable SMS reply test for event ${sourceEventId}. Only the approved test number is invited.`;
  const existing = await getEventById(db, testEventId);
  if (existing) {
    if (existing.hostUserId !== testHost.id || existing.eventDescription !== marker
        || existing.invitees.length !== 1 || existing.invitees[0].phoneNumber !== phone) {
      throw new ApiError(409, "test_event_conflict", "The test event ID is already in use.");
    }
    if (existing.invitationsSent) return { eventId: testEventId, recipientCount: 1, message: smsReminderMessage(source.event) };
  }
  const now = new Date().toISOString();
  if (!existing) await putHostedEvent(db, bindings, testHost, testEventId, {
    id: testEventId, title: `${source.event.title} (SMS test)`, hostName: "Herd SMS Test",
    eventDate: source.event.eventDate, eventTimeZone: source.event.eventTimeZone,
    endDate: source.event.endDate, eventDescription: marker,
    locationName: source.event.locationName, locationAddress: source.event.locationAddress,
    rsvpDeadline: new Date(Date.now() + 3_600_000).toISOString(),
    minimumParticipants: 2, requiredGroups: [], invitationsSent: false,
    allowsAttendeesToAddGuests: false, createdAt: now,
    invitees: [{ id: randomUuid(), displayName: "SMS test recipient", phoneNumber: phone }],
  });
  // This is a test fixture, not a real event confirmation. Commit its published
  // flag and confirmation latch together before an observer can evaluate it.
  // No invitation outbox or resolution notification is created.
  await db.batch([
    db.prepare("UPDATE events SET invitations_sent = 1, updated_at = ? WHERE id = ?").bind(now, testEventId),
    db.prepare(`INSERT INTO event_resolutions
      (event_id, policy_hash, status, attending_member_ids, resolved_at, created_at, updated_at)
      VALUES (?, ?, 'confirmed', '["host"]', ?, ?, ?)`).bind(testEventId, `sms-test:${testEventId}`, now, now, now),
  ]);
  return { eventId: testEventId, recipientCount: 1, message: smsReminderMessage(source.event) };
}
