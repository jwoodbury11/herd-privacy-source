import { getBindings, getD1 } from "@/db";
import { getAuthenticatedSession } from "@/lib/backend/auth";
import { deleteHostedEvent, putHostedEvent } from "@/lib/backend/events";
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

export async function PUT(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    requireSameOrigin(request);
    const session = await getAuthenticatedSession(request);
    const { id: rawId } = await context.params;
    const eventId = requireUuid(rawId, "event ID");
    const payload = await readJsonObject(request);
    const db = await getD1();
    const bindings = await getBindings();
    const event = await putHostedEvent(
      db,
      bindings,
      session!.user,
      eventId,
      payload.event ?? payload,
    );
    const resolution = await getEventResolutionForRead(db, bindings, event);
    return jsonResponse({ event: { ...event, resolution } });
  });
}

export async function DELETE(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    requireSameOrigin(request);
    const session = await getAuthenticatedSession(request);
    const { id: rawId } = await context.params;
    const eventId = requireUuid(rawId, "event ID");
    await deleteHostedEvent(await getD1(), session!.user.id, eventId);
    return jsonResponse({ deleted: true, id: eventId });
  });
}
