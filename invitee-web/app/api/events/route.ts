import { getBindings, getD1 } from "@/db";
import { getAuthenticatedSession } from "@/lib/backend/auth";
import { getEventsForUser } from "@/lib/backend/events";
import { jsonResponse, withApiErrors } from "@/lib/backend/http";
import { attachEventResolutions } from "@/lib/backend/resolutions";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  return withApiErrors(async () => {
    const session = await getAuthenticatedSession(request);
    const db = await getD1();
    const bindings = await getBindings();
    const events = await attachEventResolutions(
      db,
      bindings,
      await getEventsForUser(db, bindings, session!.user),
    );
    return jsonResponse({ events });
  });
}
