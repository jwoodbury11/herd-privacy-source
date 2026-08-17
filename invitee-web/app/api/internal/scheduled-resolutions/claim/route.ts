import { getBindings, getD1 } from "@/db";
import { ApiError, jsonResponse, withApiErrors } from "@/lib/backend/http";
import {
  requireEmptySchedulerBody,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";
import { claimScheduledResolutionJob } from "@/lib/backend/scheduled-resolutions";

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
    await requireEmptySchedulerBody(request);

    let job;
    try {
      job = await claimScheduledResolutionJob(
        await getD1(),
        bindings,
        new Date().toISOString(),
      );
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.code === "scheduled_claim_unavailable"
      ) {
        return jsonResponse(
          {
            error: {
              code: error.code,
              message: error.message,
            },
          },
          { status: 503, headers: { "Retry-After": "5" } },
        );
      }
      throw error;
    }
    return job ? jsonResponse(job) : noContentResponse();
  });
}
