import { getBindings, getD1 } from "@/db";
import { getAuthenticatedSession } from "@/lib/backend/auth";
import { getEventById } from "@/lib/backend/events";
import {
  ApiError,
  jsonResponse,
  readJsonObject,
  requireSameOrigin,
  requireUuid,
  withApiErrors,
} from "@/lib/backend/http";
import {
  completeClientRelayEvaluation,
  startClientRelayEvaluation,
} from "@/lib/backend/resolutions";

export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ id: string }> };

async function hostedEvent(request: Request, context: RouteContext) {
  const session = await getAuthenticatedSession(request);
  const { id: rawId } = await context.params;
  const eventId = requireUuid(rawId, "event ID");
  const db = await getD1();
  const event = await getEventById(db, eventId);
  if (!event || event.hostUserId !== session!.user.id) {
    throw new ApiError(404, "event_not_found", "The event was not found.");
  }
  const { hostUserId, ...canonicalEvent } = event;
  void hostUserId;
  return { db, event: canonicalEvent };
}

export async function POST(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    requireSameOrigin(request);
    const { db, event } = await hostedEvent(request, context);
    const result = await startClientRelayEvaluation(
      db,
      await getBindings(),
      event,
    );
    if (result.kind === "relay") return jsonResponse(result.job);
    if (result.kind === "resolved") {
      return jsonResponse({ eventId: event.id, resolution: result.resolution });
    }
    return jsonResponse(
      { eventId: event.id, resolution: { status: "pending" } },
      { status: 202 },
    );
  });
}

export async function PUT(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    requireSameOrigin(request);
    const { db, event } = await hostedEvent(request, context);
    const payload = await readJsonObject(request);
    if (
      Object.keys(payload).length !== 1 ||
      !Object.hasOwn(payload, "evaluationResponse")
    ) {
      throw new ApiError(
        400,
        "invalid_request",
        "The request must contain exactly one evaluationResponse.",
      );
    }
    const resolution = await completeClientRelayEvaluation(
      db,
      await getBindings(),
      event,
      payload.evaluationResponse,
    );
    return jsonResponse({ eventId: event.id, resolution });
  });
}
