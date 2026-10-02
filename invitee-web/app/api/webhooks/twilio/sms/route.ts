import { getBindings, getD1 } from "@/db";
import { withApiErrors } from "@/lib/backend/http";
import { handleSmsRsvp } from "@/lib/backend/sms-rsvp";
import { readTwilioSms } from "@/lib/backend/twilio-webhook";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    const params = await readTwilioSms(request, bindings);
    return handleSmsRsvp(await getD1(), bindings, params);
  });
}
