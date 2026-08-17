import { getBindings, getD1 } from "@/db";
import { jsonResponse, withApiErrors } from "@/lib/backend/http";
import {
  requireEmptySchedulerBody,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";
import { runScheduledResolutionSweep } from "@/lib/backend/scheduled-resolutions";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireSchedulerAuthorization(request, bindings);
    await requireEmptySchedulerBody(request);
    const summary = await runScheduledResolutionSweep(
      await getD1(),
      bindings,
      new Date().toISOString(),
    );
    console.info("Herd authenticated scheduler sweep", summary);
    if (summary.failedCount > 0) {
      return jsonResponse(
        {
          error: {
            code: "scheduled_resolution_incomplete",
            message: "The due-event sweep was incomplete and can be retried safely.",
          },
        },
        { status: 503, headers: { "Retry-After": "5" } },
      );
    }
    return new Response(null, {
      status: 204,
      headers: {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  });
}
