import { getBindings, getD1 } from "@/db";
import {
  ApiError,
  requireUuid,
  withApiErrors,
} from "@/lib/backend/http";
import {
  readSchedulerJsonObject,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";
import { completeScheduledResolutionJob } from "@/lib/backend/scheduled-resolutions";

export const dynamic = "force-dynamic";

function noContentResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireSchedulerAuthorization(request, bindings);
    const payload = await readSchedulerJsonObject(request);
    if (
      Object.keys(payload).length !== 2 ||
      !Object.hasOwn(payload, "eventId") ||
      !Object.hasOwn(payload, "evaluationResponse")
    ) {
      throw new ApiError(
        400,
        "invalid_request",
        "The scheduler request must contain exactly eventId and evaluationResponse.",
      );
    }
    const eventId = requireUuid(payload.eventId, "eventId");

    await completeScheduledResolutionJob(
      await getD1(),
      bindings,
      eventId,
      payload.evaluationResponse,
    );
    return noContentResponse();
  });
}
