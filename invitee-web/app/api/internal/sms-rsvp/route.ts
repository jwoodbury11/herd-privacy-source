import { getBindings, getD1 } from "@/db";
import { ApiError, jsonResponse, readJsonObject, requireString, requireUuid, withApiErrors } from "@/lib/backend/http";
import { requireOperatorAuthorization } from "@/lib/backend/operator-auth";
import { prepareSmsRsvp, sendSmsRsvp } from "@/lib/backend/sms-rsvp";
import { prepareSmsRsvpTest } from "@/lib/backend/sms-rsvp-test";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireOperatorAuthorization(request, bindings);
    const body = await readJsonObject(request);
    const eventId = requireUuid(body.eventId, "event ID");
    if (body.action === "prepare_test") {
      const testEventId = requireUuid(body.testEventId, "test event ID");
      return jsonResponse(await prepareSmsRsvpTest(await getD1(), bindings, eventId, testEventId));
    }
    if (body.audience !== "unanswered") throw new ApiError(400, "invalid_audience", "Only unanswered guests can receive this follow-up.");
    const db = await getD1();
    if (body.action === "preview") {
      const { recipients, message, expiresAt } = await prepareSmsRsvp(db, bindings, eventId, body.audience);
      return jsonResponse({ recipientCount: recipients.length, message, expiresAt });
    }
    if (body.action !== "send") throw new ApiError(400, "invalid_action", "Choose preview or send.");
    const batchId = requireUuid(body.batchId, "batch ID");
    const message = body.message === undefined ? undefined : requireString(body.message, "message", { min: 1, max: 1600 });
    return jsonResponse(await sendSmsRsvp(db, bindings, eventId, body.audience, batchId, message));
  });
}
