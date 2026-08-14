import { getBindings, getD1 } from "@/db";
import { getAuthenticatedSession } from "@/lib/backend/auth";
import { addEventAttendees, getEventsForUser } from "@/lib/backend/events";
import {
  jsonResponse,
  readJsonObject,
  requireSameOrigin,
  requireUuid,
  withApiErrors,
} from "@/lib/backend/http";
import { getEventResolutionForRead } from "@/lib/backend/resolutions";

export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    requireSameOrigin(request);
    const session = await getAuthenticatedSession(request);
    const { id: rawId } = await context.params;
    const eventId = requireUuid(rawId, "event ID");
    const payload = await readJsonObject(request);
    const db = await getD1();
    const bindings = await getBindings();
    await addEventAttendees(db, bindings, session!.user, eventId, payload);
    const event = (await getEventsForUser(db, bindings, session!.user)).find(
      (candidate) => candidate.id === eventId,
    );
    if (!event) throw new Error("The updated event could not be loaded.");
    const resolution = await getEventResolutionForRead(db, bindings, event);
    return jsonResponse({ event: { ...event, resolution } });
  });
}
